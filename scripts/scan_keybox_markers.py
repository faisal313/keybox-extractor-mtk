#!/usr/bin/env python3
"""Search partition dumps for Widevine / Android attestation keybox markers."""
import re
import sys
from pathlib import Path

PATTERNS = [
    b"<Keybox",
    b"keybox",
    b"AndroidAttestation",
    b"Widevine",
    b"MSTAR_SECURE",
    b"INNER_MSTAR",
    b"DeviceID",
    b"PrivateKey",
    b"Certificate",
]


def scan_file(path: Path) -> list[tuple[int, bytes]]:
    data = path.read_bytes()
    hits = []
    text = data.decode("latin1", errors="ignore")
    for pat in PATTERNS:
        needle = pat.decode("latin1")
        for m in re.finditer(re.escape(needle), text):
            start = max(0, m.start() - 200)
            end = min(len(data), m.end() + 2000)
            hits.append((m.start(), data[start:end]))
    return hits


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    dump_dir = root / "dumps"
    dump_dir.mkdir(exist_ok=True)
    files = sorted(dump_dir.glob("*.bin")) + sorted(dump_dir.glob("*.img"))
    if not files:
        print(f"No dump files in {dump_dir}")
        print("Run dump_partitions.ps1 first.")
        return 1
    found_any = False
    for f in files:
        print(f"\n=== {f.name} ({f.stat().st_size} bytes) ===")
        hits = scan_file(f)
        if not hits:
            print("  No keybox markers found.")
            continue
        found_any = True
        out = dump_dir / f"{f.stem}_keybox_snippet.txt"
        with out.open("wb") as w:
            for off, chunk in hits:
                w.write(f"\n--- offset 0x{off:x} ---\n".encode())
                w.write(chunk)
                w.write(b"\n")
        print(f"  Found {len(hits)} marker(s) -> {out.name}")
    return 0 if found_any else 2


if __name__ == "__main__":
    sys.exit(main())
