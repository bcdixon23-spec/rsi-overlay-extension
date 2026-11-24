"""TLS certificate and protocol checks."""

from __future__ import annotations

import asyncio
import ssl
import warnings
from datetime import datetime, timezone

from sightline.checks import CheckContext, CheckInfo, service_check
from sightline.checks.x509 import Certificate, DERError, parse_certificate
from sightline.models import Finding, Service
from sightline.netscan import insecure_tls_context


async def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float):
    _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout)
    try:
        obj = writer.get_extra_info("ssl_object")
        return obj.getpeercert(binary_form=True), obj.version()
    finally:
        writer.close()


async def get_certificate(svc: Service, ctx: CheckContext) -> tuple[Certificate | None, str]:
    key = ("tls-cert", svc.host, svc.port)
    if key not in ctx.cache:
        result: tuple[Certificate | None, str] = (None, "")
        try:
            der, version = await _handshake(svc.host, svc.port, insecure_tls_context(), ctx.timeout)
            if der:
                result = (parse_certificate(der), version or "")
        except (OSError, asyncio.TimeoutError, ssl.SSLError, DERError, ValueError, IndexError):
            pass
        ctx.cache[key] = result
    return ctx.cache[key]


def _is_tls(s: Service) -> bool:
    return s.tls


@service_check(
    _is_tls,
    id="TLS-CERT-EXPIRED",
    title="TLS certificate has expired",
    severity="high",
    category="network",
    description="Clients will reject or warn about this certificate, and users get trained to "
    "click through security warnings.",
    remediation="Renew the certificate and automate renewal (e.g. ACME / Let's Encrypt).",
)
async def cert_expired(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    cert, _ = await get_certificate(svc, ctx)
    if not cert or not cert.not_after:
        return []
    now = datetime.now(timezone.utc)
    if cert.not_after < now:
        days = (now - cert.not_after).days
        return [info.finding(svc.host, port=svc.port,
                             evidence=f"CN={cert.subject_cn}; expired {cert.not_after:%Y-%m-%d} ({days} days ago)")]  # fmt: skip
    return []


@service_check(
    _is_tls,
    id="TLS-CERT-EXPIRING",
    title="TLS certificate expires within 30 days",
    severity="medium",
    category="network",
    description="The certificate will expire soon and cause an outage if it is not renewed.",
    remediation="Renew the certificate and automate renewal.",
)
async def cert_expiring(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    cert, _ = await get_certificate(svc, ctx)
    if not cert or not cert.not_after:
        return []
    remaining = (cert.not_after - datetime.now(timezone.utc)).days
    if 0 <= remaining <= 30:
        return [info.finding(svc.host, port=svc.port,
                             evidence=f"CN={cert.subject_cn}; expires {cert.not_after:%Y-%m-%d} ({remaining} days)")]  # fmt: skip
    return []


@service_check(
    _is_tls,
    id="TLS-SELF-SIGNED",
    title="Self-signed TLS certificate",
    severity="medium",
    category="network",
    description="Clients cannot verify a self-signed certificate, which makes "
    "man-in-the-middle attacks undetectable to users who accept the warning.",
    remediation="Use a certificate from a public CA or your internal CA, and distribute the CA "
    "to clients.",
)
async def cert_self_signed(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    cert, _ = await get_certificate(svc, ctx)
    if not cert or not cert.self_signed:
        return []
    sev = info.severity if ctx.public else "low"
    return [info.finding(svc.host, port=svc.port, severity=sev, evidence=f"Issuer = Subject = CN={cert.subject_cn}")]


@service_check(
    _is_tls,
    id="TLS-WEAK-KEY",
    title="TLS certificate uses a weak key",
    severity="high",
    category="network",
    description="RSA keys shorter than 2048 bits can be factored with modest resources.",
    remediation="Reissue the certificate with an RSA 2048+ or ECDSA P-256+ key.",
)
async def cert_weak_key(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    cert, _ = await get_certificate(svc, ctx)
    if not cert or cert.key_type != "RSA" or not cert.key_bits or cert.key_bits >= 2048:
        return []
    return [info.finding(svc.host, port=svc.port, evidence=f"RSA {cert.key_bits}-bit key")]


@service_check(
    _is_tls,
    id="TLS-WEAK-SIGNATURE",
    title="TLS certificate signed with a broken hash (MD5/SHA-1)",
    severity="medium",
    category="network",
    description="MD5 and SHA-1 signatures are vulnerable to collision attacks and rejected by "
    "modern clients.",
    remediation="Reissue the certificate with a SHA-256 (or stronger) signature.",
)
async def cert_weak_signature(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    cert, _ = await get_certificate(svc, ctx)
    if not cert or not cert.weak_signature:
        return []
    return [info.finding(svc.host, port=svc.port, evidence=f"Signature algorithm: {cert.weak_signature}")]


@service_check(
    lambda s: s.tls,
    id="TLS-HOSTNAME-MISMATCH",
    title="TLS certificate does not match the hostname",
    severity="medium",
    category="network",
    description="The certificate is not valid for the name clients use to connect, so they "
    "will show security errors.",
    remediation="Issue a certificate whose Subject Alternative Names include this hostname.",
)
async def cert_mismatch(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    if not ctx.hostname:
        return []
    cert, _ = await get_certificate(svc, ctx)
    if not cert or cert.matches_host(ctx.hostname):
        return []
    names = ", ".join(cert.dns_names[:5]) or cert.subject_cn
    return [info.finding(svc.host, port=svc.port, evidence=f"Connected as {ctx.hostname}; certificate covers {names}")]


async def _accepts(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool | None:
    ctx = insecure_tls_context()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # probing old versions is the point
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        return None
    try:
        await _handshake(host, port, ctx, timeout)
        return True
    except ssl.SSLError as exc:
        text = str(exc).lower()
        if "no protocols available" in text or "unsupported protocol" in text and "local" in text:
            return None  # our OpenSSL cannot speak this version; inconclusive
        return False
    except (OSError, asyncio.TimeoutError):
        return False


@service_check(
    _is_tls,
    id="TLS-LEGACY-PROTOCOL",
    title="Server accepts obsolete TLS 1.0 / 1.1",
    severity="medium",
    category="network",
    description="TLS 1.0 and 1.1 are deprecated (RFC 8996) and lack modern cipher suites; "
    "PCI DSS and most compliance frameworks forbid them.",
    remediation="Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.",
    references=["https://www.rfc-editor.org/rfc/rfc8996"],
)
async def legacy_tls(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    accepted = []
    for label, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        if await _accepts(svc.host, svc.port, version, ctx.timeout):
            accepted.append(label)
    if not accepted:
        return []
    return [info.finding(svc.host, port=svc.port, evidence=f"Handshake succeeded with {', '.join(accepted)}")]
