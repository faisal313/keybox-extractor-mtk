#!/usr/bin/env python3
"""Check extracted keybox certificate validity."""
import argparse
import base64
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def check_keybox(path: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "file": str(path.name),
        "device_id": None,
        "private_keys": 0,
        "certificates": 0,
        "all_valid": False,
        "validity_checked": False,
        "certs": [],
        "error": None,
    }

    if not path.exists():
        result["error"] = f"file not found: {path}"
        return result

    xml = path.read_text(encoding="utf-8")
    result["size_bytes"] = path.stat().st_size
    m = re.search(r'DeviceID="([^"]+)"', xml)
    result["device_id"] = m.group(1) if m else None
    result["private_keys"] = xml.count("BEGIN EC PRIVATE KEY") + xml.count("BEGIN RSA PRIVATE KEY")
    result["certificates"] = xml.count("BEGIN CERTIFICATE")

    if result["private_keys"] == 0:
        result["error"] = "no private keys found in keybox"
        return result

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        result["error"] = "cryptography not installed (pip install cryptography)"
        return result

    now = datetime.now(timezone.utc)
    certs_b64 = re.findall(
        r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)\n-----END CERTIFICATE-----",
        xml,
    )
    result["validity_checked"] = True
    all_valid = bool(certs_b64)

    for i, b64 in enumerate(certs_b64):
        der = base64.b64decode(b64.replace("\n", ""))
        cert = x509.load_der_x509_certificate(der, default_backend())
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
        ok = nb <= now <= na
        all_valid = all_valid and ok
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        cn_s = cn[0].value if cn else cert.subject.rfc4514_string()[:80]
        result["certs"].append({
            "index": i,
            "valid": ok,
            "not_before": nb.isoformat(),
            "not_after": na.isoformat(),
            "common_name": cn_s,
        })

    result["all_valid"] = all_valid
    result["checked_at"] = now.isoformat()
    return result


def print_report(result: Dict[str, Any]) -> None:
    if result.get("error") and not result.get("validity_checked"):
        print(f"ERROR: {result['error']}")
        return

    print(f"File: {result.get('file')} ({result.get('size_bytes', 0)} bytes)")
    print(f"DeviceID: {result.get('device_id') or 'n/a'}")
    print(f"Private keys: {result.get('private_keys', 0)}")
    print(f"Certificates: {result.get('certificates', 0)}")

    if not result.get("validity_checked"):
        if result.get("error"):
            print(f"WARN: {result['error']}")
        return

    print(f"\nCertificate validity ({len(result['certs'])} certs):")
    for c in result["certs"]:
        status = "VALID" if c["valid"] else "EXPIRED/NOT YET"
        nb = c["not_before"][:10]
        na = c["not_after"][:10]
        print(f"  [{c['index']}] {status}  {nb} -> {na}  CN={c['common_name']}")

    print(f"\nKeybox valid: {result['all_valid']}")


def find_keybox(dumps: Path, explicit: Optional[Path]) -> Optional[Path]:
    if explicit:
        return explicit
    candidates = sorted(dumps.glob("*_Pvt_kb.xml"))
    return candidates[0] if candidates else None


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    dumps = root / "dumps"
    parser = argparse.ArgumentParser(description="Check keybox certificate validity")
    parser.add_argument("-i", "--input", help="keybox XML (default: dumps/*_Pvt_kb.xml)")
    parser.add_argument("-o", "--json-out", help="write validity report JSON to this path")
    args = parser.parse_args()

    keybox_path = find_keybox(dumps, Path(args.input) if args.input else None)
    if not keybox_path or not keybox_path.exists():
        print("ERROR: keybox XML not found")
        return 2

    result = check_keybox(keybox_path)
    print_report(result)

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nReport saved: {out}")

    if result.get("error") and not result.get("validity_checked"):
        return 2
    if not result.get("all_valid"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
