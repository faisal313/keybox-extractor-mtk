#!/usr/bin/env python3
"""Report keybox format across all partition dumps."""
import re
import sys
from pathlib import Path


def analyze(path: Path) -> dict:
    result = {
        "path": path,
        "att": 0,
        "kb": 0,
        "pem_priv": 0,
        "pem_cert": 0,
        "wv": 0,
        "device_id": None,
        "format": "no keybox markers",
    }
    if not path.exists():
        return result
    d = path.read_bytes()
    result["att"] = len(re.findall(rb"<AndroidAttestation>", d))
    result["kb"] = len(re.findall(rb"<Keybox", d))
    result["pem_priv"] = d.count(b"BEGIN EC PRIVATE KEY") + d.count(b"BEGIN RSA PRIVATE KEY")
    result["pem_cert"] = d.count(b"BEGIN CERTIFICATE")
    result["wv"] = len(re.findall(rb"widevine", d, re.I))
    m = re.search(rb'DeviceID="([^"]+)"', d)
    if m:
        result["device_id"] = m.group(1).decode()
    if result["att"] > 0 and result["pem_priv"] > 0:
        result["format"] = "plaintext XML + PEM in partition"
    elif result["kb"] > 0 or result["wv"] > 0:
        result["format"] = "keybox-related strings present"
    return result


def print_report(path: Path) -> dict:
    info = analyze(path)
    if not path.exists():
        print(f"  (missing {path.name})")
        return info
    size = path.stat().st_size
    print(f"\n=== {path.name} ({size} bytes) ===")
    print(f"  AndroidAttestation blocks: {info['att']}")
    print(f"  Keybox tags: {info['kb']}")
    print(f"  PEM private keys: {info['pem_priv']}")
    print(f"  PEM certificates: {info['pem_cert']}")
    print(f"  widevine mentions: {info['wv']}")
    if info["device_id"]:
        print(f"  DeviceID: {info['device_id']}")
    print(f"  Format: {info['format']}")
    return info


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    dumps = root / "dumps"
    dump_files = sorted(dumps.glob("*.bin")) + sorted(dumps.glob("*.img"))
    snippet_files = sorted(dumps.glob("*_keybox_snippet.txt"))
    xml_files = sorted(dumps.glob("*.xml"))

    if not dump_files and not snippet_files and not xml_files:
        print("No dumps yet. Run dump_partitions.ps1 first.")
        return 1

    reports = []
    for f in dump_files:
        reports.append(print_report(f))

    for f in snippet_files:
        print_report(f)

    for xf in xml_files:
        print_report(xf)

    best = max(reports, key=lambda r: (r["att"], r["pem_priv"], r["kb"]), default=None)
    if best and best["att"] > 0:
        print(f"\nBest extraction candidate: {best['path'].name}")
    elif reports:
        print("\nNo AndroidAttestation block found yet. Check protect1/protect2 snippets or vendor partitions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
