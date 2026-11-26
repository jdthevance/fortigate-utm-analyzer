"""Read the facts an auditor needs from a PEM certificate, with no libraries.

FortiWeb backups store certificates as PEM text inside
``config system certificate local`` (``set certificate "-----BEGIN ..."``).
This module decodes just enough of the X.509 DER structure to report:
expiry dates, key type and size, signature hash, subject CN, and whether the
certificate is self-signed.

It is deliberately small. Anything it cannot decode is reported as
"unreadable" rather than guessed.

Go mapping: not needed as a package. Go's standard ``crypto/x509`` parses
certificates; ``internal/fortiweb/certs`` only wraps it.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)

SIG_ALGS = {
    "1.2.840.113549.1.1.4": "md5WithRSA",
    "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.1": "ecdsaWithSHA1",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.3.101.112": "ed25519",
}
WEAK_SIGS = ("md5WithRSA", "sha1WithRSA", "ecdsaWithSHA1")
CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
}
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_CN = "2.5.4.3"


@dataclass
class CertInfo:
    subject_cn: str
    issuer_cn: str
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    key_type: str            # RSA / EC / Ed25519 / unknown
    key_bits: int
    signature: str
    self_signed: bool

    @property
    def weak_signature(self) -> bool:
        return self.signature in WEAK_SIGS


class DerError(ValueError):
    pass


def _tlv(data: bytes, pos: int) -> Tuple[int, int, int]:
    """Return (tag, start of value, end of value) for the element at pos."""
    if pos + 2 > len(data):
        raise DerError("truncated")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise DerError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise DerError("truncated")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> List[Tuple[int, int, int]]:
    out = []
    pos = start
    while pos < end:
        tag, vs, ve = _tlv(data, pos)
        out.append((tag, vs, ve))
        pos = ve
    return out


def _oid(raw: bytes) -> str:
    if not raw:
        return ""
    parts = [raw[0] // 40, raw[0] % 40]
    value = 0
    for b in raw[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _time(tag: int, raw: bytes) -> Optional[datetime]:
    text = raw.decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 0x17:          # UTCTime YYMMDDHHMMSS
            dt = datetime.strptime(text[:12], "%y%m%d%H%M%S")
        else:                    # GeneralizedTime YYYYMMDDHHMMSS
            dt = datetime.strptime(text[:14], "%Y%m%d%H%M%S")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc)


def _cn(data: bytes, start: int, end: int) -> str:
    for _, s, e in _children(data, start, end):              # SET
        for _, s2, e2 in _children(data, s, e):              # SEQUENCE
            parts = _children(data, s2, e2)
            if len(parts) == 2 and _oid(data[parts[0][1]:parts[0][2]]) == OID_CN:
                return data[parts[1][1]:parts[1][2]].decode("utf-8", "replace")
    return ""


def parse_der(der: bytes) -> CertInfo:
    _, cs, ce = _tlv(der, 0)                                 # Certificate
    cert = _children(der, cs, ce)
    _, ts, te = cert[0]                                      # tbsCertificate
    tbs = _children(der, ts, te)
    i = 1 if tbs[0][0] == 0xA0 else 0                        # optional [0] version
    # serial = tbs[i]; signature alg = tbs[i+1]
    issuer, validity, subject, spki = tbs[i + 2], tbs[i + 3], tbs[i + 4], tbs[i + 5]
    times = _children(der, validity[1], validity[2])
    not_before = _time(times[0][0], der[times[0][1]:times[0][2]])
    not_after = _time(times[1][0], der[times[1][1]:times[1][2]])

    key_type, bits = "unknown", 0
    alg, key = _children(der, spki[1], spki[2])
    alg_parts = _children(der, alg[1], alg[2])
    key_oid = _oid(der[alg_parts[0][1]:alg_parts[0][2]])
    if key_oid == OID_RSA:
        key_type = "RSA"
        bitstr = der[key[1] + 1:key[2]]                      # skip "unused bits" byte
        _, rs, re_ = _tlv(bitstr, 0)
        modulus = _children(bitstr, rs, re_)[0]
        n = int.from_bytes(bitstr[modulus[1]:modulus[2]], "big")
        bits = n.bit_length()
    elif key_oid == OID_EC:
        key_type = "EC"
        if len(alg_parts) > 1:
            curve = _oid(der[alg_parts[1][1]:alg_parts[1][2]])
            bits = CURVES.get(curve, ("", 0))[1]
    elif key_oid == OID_ED25519:
        key_type, bits = "Ed25519", 256

    sig_parts = _children(der, cert[1][1], cert[1][2])
    signature = SIG_ALGS.get(_oid(der[sig_parts[0][1]:sig_parts[0][2]]), "unknown")
    issuer_raw = der[issuer[1]:issuer[2]]
    subject_raw = der[subject[1]:subject[2]]
    return CertInfo(
        subject_cn=_cn(der, subject[1], subject[2]),
        issuer_cn=_cn(der, issuer[1], issuer[2]),
        not_before=not_before, not_after=not_after,
        key_type=key_type, key_bits=bits, signature=signature,
        self_signed=issuer_raw == subject_raw,
    )


def parse_pem(text: str) -> Optional[CertInfo]:
    """First certificate in a PEM blob, or None if there is none or it is unreadable."""
    if not text:
        return None
    m = PEM_RE.search(text.replace("\\n", "\n"))
    if not m:
        return None
    try:
        der = base64.b64decode("".join(m.group(1).split()))
        return parse_der(der)
    except (ValueError, IndexError, DerError):
        return None
