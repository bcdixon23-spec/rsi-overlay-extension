"""Minimal DER/X.509 parser - just enough to audit TLS certificates.

The standard library only decodes certificates it has verified, and a scanner
needs to inspect the broken ones too, so we parse the DER ourselves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

OID_CN = "2.5.4.3"
OID_SAN = "2.5.29.17"
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_ED448 = "1.3.101.113"
EC_CURVES = {"1.2.840.10045.3.1.7": 256, "1.3.132.0.34": 384, "1.3.132.0.35": 521}
WEAK_SIGNATURES = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10040.4.3": "dsa-with-sha1",
}


class DERError(ValueError):
    pass


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    if pos + 2 > len(data):
        raise DERError("truncated")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise DERError("bad length")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise DERError("value overruns buffer")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
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


def _time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        year = int(text[:2])
        year += 2000 if year < 50 else 1900
        rest = text[2:]
    else:  # GeneralizedTime YYYYMMDDHHMMSSZ
        year = int(text[:4])
        rest = text[4:]
    return datetime(
        year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]),
        int(rest[8:10]) if len(rest) >= 10 and rest[8:10].isdigit() else 0,
        tzinfo=timezone.utc,
    )  # fmt: skip


def _name_cn(data: bytes, start: int, end: int) -> str:
    for _, ss, se in _children(data, start, end):  # SET
        for _, as_, ae in _children(data, ss, se):  # AttributeTypeAndValue
            parts = _children(data, as_, ae)
            if len(parts) == 2 and _oid(data[parts[0][1] : parts[0][2]]) == OID_CN:
                return data[parts[1][1] : parts[1][2]].decode("utf-8", "replace")
    return ""


@dataclass
class Certificate:
    subject_cn: str = ""
    issuer_cn: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    self_signed: bool = False
    key_type: str = ""
    key_bits: int = 0
    signature_oid: str = ""
    dns_names: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)

    @property
    def weak_signature(self) -> str | None:
        return WEAK_SIGNATURES.get(self.signature_oid)

    def matches_host(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        names = self.dns_names or ([self.subject_cn] if self.subject_cn else [])
        for name in names:
            name = name.lower().rstrip(".")
            if name == host:
                return True
            if name.startswith("*.") and "." in host:
                if host.split(".", 1)[1] == name[2:]:
                    return True
        return host in self.ip_addresses


def parse_certificate(der: bytes) -> Certificate:
    cert = Certificate()
    _, cs, ce = _tlv(der, 0)
    top = _children(der, cs, ce)
    if len(top) < 3:
        raise DERError("not a certificate")
    _, ts, te = top[0]
    sig_alg = _children(der, top[1][1], top[1][2])
    cert.signature_oid = _oid(der[sig_alg[0][1] : sig_alg[0][2]]) if sig_alg else ""

    fields = _children(der, ts, te)
    idx = 0
    if fields and fields[0][0] == 0xA0:  # explicit version
        idx = 1
    # serial, signature, issuer, validity, subject, spki
    _serial, _sig, issuer, validity, subject, spki = fields[idx : idx + 6]
    cert.issuer_cn = _name_cn(der, issuer[1], issuer[2])
    cert.subject_cn = _name_cn(der, subject[1], subject[2])
    cert.self_signed = der[issuer[1] : issuer[2]] == der[subject[1] : subject[2]]
    times = _children(der, validity[1], validity[2])
    if len(times) == 2:
        cert.not_before = _time(times[0][0], der[times[0][1] : times[0][2]])
        cert.not_after = _time(times[1][0], der[times[1][1] : times[1][2]])

    spki_parts = _children(der, spki[1], spki[2])
    alg = _children(der, spki_parts[0][1], spki_parts[0][2])
    key_oid = _oid(der[alg[0][1] : alg[0][2]])
    if key_oid == OID_RSA:
        cert.key_type = "RSA"
        bit_string = der[spki_parts[1][1] + 1 : spki_parts[1][2]]
        _, rs, re_ = _tlv(bit_string, 0)
        rsa = _children(bit_string, rs, re_)
        modulus = bit_string[rsa[0][1] : rsa[0][2]].lstrip(b"\x00")
        cert.key_bits = len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else 0
    elif key_oid == OID_EC:
        cert.key_type = "EC"
        if len(alg) > 1 and alg[1][0] == 0x06:
            cert.key_bits = EC_CURVES.get(_oid(der[alg[1][1] : alg[1][2]]), 0)
    elif key_oid in (OID_ED25519, OID_ED448):
        cert.key_type = "EdDSA"
        cert.key_bits = 256 if key_oid == OID_ED25519 else 456
    else:
        cert.key_type = key_oid

    for tag, vs, ve in fields[idx + 6 :]:
        if tag != 0xA3:
            continue
        exts = _children(der, vs, ve)
        if not exts:
            continue
        for _, es, ee in _children(der, exts[0][1], exts[0][2]):
            parts = _children(der, es, ee)
            if not parts or _oid(der[parts[0][1] : parts[0][2]]) != OID_SAN:
                continue
            octet = parts[-1]
            inner = der[octet[1] : octet[2]]
            _, gs, ge = _tlv(inner, 0)
            for gtag, ns, ne in _children(inner, gs, ge):
                if gtag == 0x82:
                    cert.dns_names.append(inner[ns:ne].decode("ascii", "replace"))
                elif gtag == 0x87 and ne - ns == 4:
                    cert.ip_addresses.append(".".join(str(b) for b in inner[ns:ne]))
    return cert
