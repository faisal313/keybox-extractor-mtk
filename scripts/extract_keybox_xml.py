#!/usr/bin/env python3
"""Extract AndroidAttestation keybox XML from MTK partition dumps."""
import argparse
import re
import sys
from pathlib import Path
from typing import Optional


def extract_keybox_xml(data: bytes) -> str:
    blocks = re.findall(rb"<AndroidAttestation>.*?</AndroidAttestation>", data, re.DOTALL)
    if not blocks:
        raise ValueError("No <AndroidAttestation> block found")
    block = max(blocks, key=len)
    text = block.decode("utf-8", errors="replace").strip()
    if not text.startswith("<?xml"):
        text = '<?xml version="1.0" encoding="UTF-8"?>\n' + text
    return text + "\n"


def score_dump(path: Path) -> tuple[int, int, int]:
    data = path.read_bytes()
    att = len(re.findall(rb"<AndroidAttestation>", data))
    pem = data.count(b"BEGIN EC PRIVATE KEY") + data.count(b"BEGIN RSA PRIVATE KEY")
    kb = len(re.findall(rb"<Keybox", data))
    return (att, pem, kb)


def find_best_dump(dumps_dir: Path) -> Optional[Path]:
    candidates = sorted(dumps_dir.glob("*.bin")) + sorted(dumps_dir.glob("*.img"))
    if not candidates:
        return None
    ranked = sorted(candidates, key=score_dump, reverse=True)
    best_score = score_dump(ranked[0])
    if best_score[0] > 0:
        return ranked[0]
    return ranked[0] if best_score[2] > 0 or best_score[1] > 0 else None


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    dumps = root / "dumps"
    parser = argparse.ArgumentParser(description="Extract keybox XML from MTK partition dumps")
    parser.add_argument(
        "-i", "--input",
        default="",
        help="partition dump (default: auto-detect best dumps/*.bin)",
    )
    parser.add_argument(
        "-o", "--output",
        default=str(dumps / "device_keybox.xml"),
        help="output XML path",
    )
    args = parser.parse_args()

    if args.input:
        src = Path(args.input)
    else:
        src = find_best_dump(dumps)
        if not src and (dumps / "persist.bin").exists():
            src = dumps / "persist.bin"
        if src:
            print(f"Using input: {src}")

    if not src or not src.exists():
        print("ERROR: No partition dump found. Run dump_partitions.ps1 first.")
        return 1

    try:
        xml = extract_keybox_xml(src.read_bytes())
    except ValueError as exc:
        print(f"ERROR: {exc} in {src.name}")
        print("Try another partition: python extract_keybox_xml.py -i dumps/protect1.bin")
        return 1

    dst = Path(args.output)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(xml, encoding="utf-8", newline="\n")
    print(f"Wrote {dst} ({dst.stat().st_size} bytes)")
    m = re.search(r'DeviceID="([^"]+)"', xml)
    print(f"DeviceID: {m.group(1) if m else 'unknown'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
