"""Regenerate the test certificates embedded in the FortiWeb fixtures.

Developer tool only (needs the 'cryptography' package); the analyzer itself
reads certificates with the standard library. Prints PEM blocks to paste.

The expired, self-signed, 1024-bit SHA-1 "portal-legacy" certificate cannot be
made with current 'cryptography' (SHA-1 signing is refused). It was made with
OpenSSL 3.0, using a minimal ca.cnf (default_md sha1, policy commonName=supplied):

    openssl req -new -newkey rsa:1024 -nodes -keyout k.pem -out r.csr -config ca.cnf
    openssl ca -batch -config ca.cnf -selfsign -keyfile k.pem -in r.csr -out legacy.pem \
        -startdate 20220101000000Z -enddate 20240101000000Z -md sha1 -notext
"""
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make(cn, issuer_cn, bits, digest, start, end):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer_cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(end).sign(key, digest))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def d(y, m, day):
    return datetime(y, m, day, tzinfo=timezone.utc)


if __name__ == "__main__":
    print("# shop-cert\n" + make("shop.example.com", "Example Issuing CA", 2048, hashes.SHA256(), d(2026, 1, 1), d(2028, 1, 1)))
    print("# www-cert\n" + make("www.example.com", "Example Issuing CA", 2048, hashes.SHA256(), d(2026, 6, 1), d(2030, 6, 1)))
