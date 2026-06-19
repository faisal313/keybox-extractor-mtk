#!/usr/bin/env python3
import argparse
import base64
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID


def find_keybox_xml(dumps: Path) -> Optional[Path]:
    candidates = sorted(dumps.glob("*_Pvt_kb.xml")) + sorted(dumps.glob("*keybox*.xml"))
    return candidates[0] if candidates else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect keybox certificate chain")
    parser.add_argument("-i", "--input", help="keybox XML (default: dumps/*_Pvt_kb.xml)")
    args = parser.parse_args()

    dumps = Path(__file__).resolve().parent.parent / "dumps"
    if args.input:
        p = Path(args.input)
    else:
        p = find_keybox_xml(dumps)
    if not p or not p.exists():
        print("ERROR: keybox XML not found")
        return 1

    xml = p.read_text(encoding="utf-8")
    certs_b64 = re.findall(
        r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)\n-----END CERTIFICATE-----",
        xml,
    )

    now = datetime.now(timezone.utc)
    print(f"File: {p.name} ({p.stat().st_size} bytes)")
    for i, b64 in enumerate(certs_b64):
        der = base64.b64decode(b64.replace("\n", ""))
        cert = x509.load_der_x509_certificate(der, default_backend())
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
        ok = nb <= now <= na
        print(f"\n=== Certificate [{i}] {'VALID' if ok else 'EXPIRED'} ===")
        print(f"  notBefore: {nb}")
        print(f"  notAfter:  {na}")
        print(f"  Subject:   {cert.subject.rfc4514_string()}")
        print(f"  Issuer:    {cert.issuer.rfc4514_string()}")
        print(f"  Serial:    {hex(cert.serial_number)}")
        try:
            ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest.hex()
            print(f"  SKI:       {ski}")
        except Exception:
            pass
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            print(f"  CA cert:   {bc.ca}")
            if bc.ca:
                print(f"  path len:  {bc.path_length}")
        except Exception:
            pass
        for oid in [NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME, NameOID.ORGANIZATIONAL_UNIT_NAME]:
            attrs = cert.subject.get_attributes_for_oid(oid)
            if attrs:
                print(f"  {oid.name}: {attrs[0].value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
