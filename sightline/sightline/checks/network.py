"""Unauthenticated network exposure checks.

Every probe here is read-only and safe: we perform handshakes and harmless
queries (PING, version, list databases) and never write data or try exploits.
"""

from __future__ import annotations

import asyncio
import re
import socket
import struct

from sightline.checks import CheckContext, CheckInfo, host_network_check, service_check
from sightline.models import Finding, Service
from sightline.netscan import http_get, try_exchange
from sightline.vulndb.versions import compare_dpkg

# ------------------------------------------------------------------ telnet


@service_check(
    lambda s: s.name == "telnet",
    id="NET-TELNET",
    title="Telnet service exposed",
    severity="high",
    category="network",
    description="Telnet sends usernames, passwords and session data in cleartext, so anyone "
    "on the network path can capture credentials.",
    remediation="Disable telnet and use SSH instead.",
)
async def telnet_exposed(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    sev = "critical" if ctx.public else info.severity
    return [info.finding(svc.host, port=svc.port, severity=sev, evidence=svc.banner or "")]


# --------------------------------------------------------------------- ftp


async def _ftp_reply(reader: asyncio.StreamReader, timeout: float) -> str:
    lines = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout)
        if not line:
            break
        text = line.decode("latin-1", "replace").rstrip()
        lines.append(text)
        if len(text) >= 4 and text[:3].isdigit() and text[3] == " ":
            break
        if len(text) == 3 and text.isdigit():
            break
    return "\n".join(lines)


async def ftp_session(host: str, port: int, commands: list[str], timeout: float) -> list[str]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    replies = []
    try:
        replies.append(await _ftp_reply(reader, timeout))
        for cmd in commands:
            writer.write(cmd.encode() + b"\r\n")
            await writer.drain()
            replies.append(await _ftp_reply(reader, timeout))
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()
    return replies


@service_check(
    lambda s: s.name == "ftp",
    id="NET-FTP-ANON",
    title="FTP server allows anonymous login",
    severity="high",
    category="network",
    description="Anyone can log in to this FTP server without a password and read (and "
    "possibly write) files.",
    remediation="Disable anonymous access (e.g. anonymous_enable=NO in vsftpd) unless the "
    "server is intentionally public, and then make sure it is read-only.",
)
async def ftp_anonymous(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    try:
        replies = await ftp_session(
            svc.host, svc.port, ["USER anonymous", "PASS sightline@example.com"], ctx.timeout
        )
    except (OSError, asyncio.TimeoutError):
        return []
    logged_in = any(r.startswith("230") for r in replies[1:3])
    if not logged_in:
        return []
    return [info.finding(svc.host, port=svc.port, evidence="USER anonymous -> 230 Login successful")]


@service_check(
    lambda s: s.name == "ftp",
    id="NET-FTP-CLEARTEXT",
    title="FTP server does not support encryption",
    severity="medium",
    category="network",
    description="The FTP server does not offer AUTH TLS, so credentials and files cross the "
    "network unencrypted.",
    remediation="Enable FTPS (AUTH TLS) or replace FTP with SFTP.",
)
async def ftp_cleartext(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    try:
        replies = await ftp_session(svc.host, svc.port, ["AUTH TLS"], ctx.timeout)
    except (OSError, asyncio.TimeoutError):
        return []
    if len(replies) < 2 or replies[1].startswith("234"):
        return []
    return [info.finding(svc.host, port=svc.port, evidence=f"AUTH TLS -> {replies[1][:80]}")]


# ------------------------------------------------------------------- redis


@service_check(
    lambda s: s.name == "redis",
    id="NET-REDIS-NOAUTH",
    title="Redis accepts commands without authentication",
    severity="critical",
    category="network",
    description="Anyone who can reach this port can read and modify all cached data, and an "
    "open Redis is a well-known path to remote code execution (writing SSH keys or cron "
    "jobs via CONFIG SET).",
    remediation="Set a strong password (requirepass) or ACL users, bind Redis to localhost or "
    "a private interface, and keep protected-mode enabled.",
    references=["https://redis.io/docs/latest/operate/oss_and_stack/management/security/"],
)
async def redis_noauth(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    reply = await try_exchange(svc.host, svc.port, b"INFO server\r\n", timeout=ctx.timeout,
                               read_bytes=8192, read_all=True)  # fmt: skip
    text = reply.decode("latin-1", "replace")
    if not text.startswith("$") or "redis_version" not in text:
        return []
    m = re.search(r"redis_version:([\d.]+)", text)
    version = m.group(1) if m else "unknown"
    svc.version = svc.version or version
    return [
        info.finding(
            svc.host, port=svc.port, evidence=f"INFO server answered without AUTH (redis {version})"
        )
    ]


# --------------------------------------------------------------- memcached


@service_check(
    lambda s: s.name == "memcached",
    id="NET-MEMCACHED-OPEN",
    title="Memcached exposed without authentication",
    severity="high",
    category="network",
    description="Memcached has no authentication by default: anyone can read or poison cached "
    "data, and exposed instances are abused for DDoS amplification.",
    remediation="Bind memcached to localhost (-l 127.0.0.1), disable UDP (-U 0) and firewall "
    "the port.",
)
async def memcached_open(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    reply = await try_exchange(svc.host, svc.port, b"stats\r\n", timeout=ctx.timeout)
    if b"STAT pid" not in reply:
        return []
    sev = "critical" if ctx.public else info.severity
    return [info.finding(svc.host, port=svc.port, severity=sev, evidence="'stats' answered")]


# ----------------------------------------------------------------- mongodb


def _bson_encode(items: list[tuple[str, object]]) -> bytes:
    body = b""
    for key, value in items:
        k = key.encode() + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + k + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            body += b"\x10" + k + struct.pack("<i", value)
        else:
            v = str(value).encode() + b"\x00"
            body += b"\x02" + k + struct.pack("<i", len(v)) + v
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def bson_decode(data: bytes, pos: int = 0) -> dict:
    (length,) = struct.unpack_from("<i", data, pos)
    end = pos + length - 1
    pos += 4
    out: dict = {}
    while pos < end:
        kind = data[pos]
        pos += 1
        key_end = data.index(b"\x00", pos)
        key = data[pos:key_end].decode("utf-8", "replace")
        pos = key_end + 1
        if kind == 0x01:
            out[key] = struct.unpack_from("<d", data, pos)[0]
            pos += 8
        elif kind == 0x02:
            (n,) = struct.unpack_from("<i", data, pos)
            out[key] = data[pos + 4 : pos + 4 + n - 1].decode("utf-8", "replace")
            pos += 4 + n
        elif kind in (0x03, 0x04):
            (n,) = struct.unpack_from("<i", data, pos)
            sub = bson_decode(data, pos)
            out[key] = list(sub.values()) if kind == 0x04 else sub
            pos += n
        elif kind == 0x05:
            (n,) = struct.unpack_from("<i", data, pos)
            pos += 5 + n
        elif kind == 0x07:
            pos += 12
        elif kind == 0x08:
            out[key] = data[pos] == 1
            pos += 1
        elif kind in (0x09, 0x11, 0x12):
            out[key] = struct.unpack_from("<q", data, pos)[0]
            pos += 8
        elif kind == 0x0A:
            out[key] = None
        elif kind == 0x10:
            out[key] = struct.unpack_from("<i", data, pos)[0]
            pos += 4
        elif kind == 0x13:
            pos += 16
        else:
            break
    return out


def mongo_op_msg(doc: list[tuple[str, object]], request_id: int = 1) -> bytes:
    payload = struct.pack("<I", 0) + b"\x00" + _bson_encode(doc)
    return struct.pack("<iiii", 16 + len(payload), request_id, 0, 2013) + payload


def mongo_op_query(doc: list[tuple[str, object]], request_id: int = 1) -> bytes:
    payload = (
        struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + _bson_encode(doc)
    )
    return struct.pack("<iiii", 16 + len(payload), request_id, 0, 2004) + payload


def mongo_parse_reply(data: bytes) -> dict | None:
    if len(data) < 21:
        return None
    (opcode,) = struct.unpack_from("<i", data, 12)
    try:
        if opcode == 2013 and data[20] == 0:
            return bson_decode(data, 21)
        if opcode == 1 and len(data) >= 41:
            return bson_decode(data, 36)
    except (struct.error, ValueError, IndexError):
        return None
    return None


@service_check(
    lambda s: s.name == "mongodb" or s.port == 27017,
    id="NET-MONGODB-NOAUTH",
    title="MongoDB allows unauthenticated access",
    severity="critical",
    category="network",
    description="The MongoDB server lists its databases to anyone without credentials. "
    "Unauthenticated MongoDB instances are routinely wiped and ransomed by automated bots.",
    remediation="Enable authorization (security.authorization: enabled), create admin users, "
    "and bind to private interfaces only (net.bindIp).",
)
async def mongodb_noauth(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    reply = mongo_parse_reply(
        await try_exchange(
            svc.host, svc.port,
            mongo_op_msg([("listDatabases", 1), ("nameOnly", True), ("$db", "admin")]),
            timeout=ctx.timeout, read_bytes=65536,
        )
    )  # fmt: skip
    if reply is None:
        reply = mongo_parse_reply(
            await try_exchange(svc.host, svc.port, mongo_op_query([("listDatabases", 1)]),
                               timeout=ctx.timeout, read_bytes=65536)  # fmt: skip
        )
    if not reply:
        return []
    svc.name, svc.product = "mongodb", "MongoDB"
    if reply.get("ok") not in (1, 1.0) or "databases" not in reply:
        return []
    names = [d.get("name", "?") for d in reply.get("databases", []) if isinstance(d, dict)]
    return [
        info.finding(
            svc.host,
            port=svc.port,
            evidence=f"listDatabases succeeded without auth: {', '.join(names[:8]) or '(none)'}",
        )
    ]


# ------------------------------------------------------- HTTP-based admin APIs


@service_check(
    lambda s: s.name in ("http", "https", "elasticsearch") and s.port in (9200, 9201)
    or s.product == "Elasticsearch",
    id="NET-ELASTIC-NOAUTH",
    title="Elasticsearch/OpenSearch API open without authentication",
    severity="critical",
    category="network",
    description="The search cluster's REST API answers without credentials, exposing every "
    "index to reading, modification and deletion.",
    remediation="Enable the security features (xpack.security.enabled: true, or the OpenSearch "
    "security plugin), require TLS and authentication, and firewall port 9200.",
)
async def elastic_noauth(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await http_get(svc.host, svc.port, "/", tls=svc.tls, timeout=ctx.timeout)
    if not resp or resp.status != 200 or '"cluster_name"' not in resp.body:
        return []
    m = re.search(r'"number"\s*:\s*"([^"]+)"', resp.body)
    svc.product, svc.version = "Elasticsearch", m.group(1) if m else ""
    return [info.finding(svc.host, port=svc.port, evidence=f"GET / -> 200 cluster info (version {svc.version or '?'})")]


@service_check(
    lambda s: s.port in (2375, 2376) or s.product == "Docker Engine API",
    id="NET-DOCKER-API",
    title="Docker Engine API exposed without authentication",
    severity="critical",
    category="network",
    description="Anyone who can reach the Docker API can start a privileged container that "
    "mounts the host filesystem - full root on the host.",
    remediation="Stop exposing dockerd over TCP (remove -H tcp://...), or require mutual TLS "
    "(--tlsverify) and firewall the port.",
    references=["https://docs.docker.com/engine/security/protect-access/"],
)
async def docker_api(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await http_get(svc.host, svc.port, "/version", tls=svc.tls, timeout=ctx.timeout)
    if not resp or resp.status != 200 or '"ApiVersion"' not in resp.body:
        return []
    m = re.search(r'"Version"\s*:\s*"([^"]+)"', resp.body)
    return [info.finding(svc.host, port=svc.port, evidence=f"GET /version -> Docker {m.group(1) if m else '?'}")]


@service_check(
    lambda s: s.port == 10250,
    id="NET-KUBELET-ANON",
    title="Kubelet API allows anonymous access",
    severity="critical",
    category="network",
    description="The kubelet answers API requests without authentication, which allows "
    "listing pods and executing commands inside containers on this node.",
    remediation="Set --anonymous-auth=false and --authorization-mode=Webhook on the kubelet.",
)
async def kubelet_anon(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await http_get(svc.host, svc.port, "/pods", tls=True, timeout=ctx.timeout)
    if not resp or resp.status != 200 or "PodList" not in resp.body:
        return []
    return [info.finding(svc.host, port=svc.port, evidence="GET /pods -> 200 PodList")]


@service_check(
    lambda s: s.port == 2379,
    id="NET-ETCD-OPEN",
    title="etcd API reachable without client authentication",
    severity="high",
    category="network",
    description="etcd stores cluster state and, in Kubernetes, every Secret. It answers here "
    "without requiring a client certificate.",
    remediation="Require client certificate auth (--client-cert-auth=true) and restrict the "
    "port to control-plane nodes.",
)
async def etcd_open(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await http_get(svc.host, svc.port, "/version", tls=svc.tls, timeout=ctx.timeout)
    if not resp or resp.status != 200 or "etcdserver" not in resp.body:
        return []
    return [info.finding(svc.host, port=svc.port, evidence=resp.body.strip()[:120])]


# --------------------------------------------------------------------- smb

SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x2f"  # NetBIOS session, length 47
    b"\xffSMB\x72\x00\x00\x00\x00\x18\x01\x28\x00\x00"
    + b"\x00" * 8
    + b"\x00\x00\x00\x00\x2f\x4b\x00\x00\xc5\x5e"
    + b"\x00\x0c\x00\x02NT LM 0.12\x00"
)


@service_check(
    lambda s: s.port == 445,
    id="NET-SMB1",
    title="SMBv1 protocol enabled",
    severity="high",
    category="network",
    description="SMBv1 is obsolete and was the vector for WannaCry and NotPetya "
    "(EternalBlue, MS17-010). It should not be enabled anywhere.",
    remediation="Disable SMBv1 (Windows: Disable-WindowsOptionalFeature -FeatureName "
    "SMB1Protocol; Samba: server min protocol = SMB2).",
    references=["https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"],
)
async def smb1(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    svc.name = "smb"
    reply = await try_exchange(svc.host, svc.port, SMB1_NEGOTIATE, timeout=ctx.timeout)
    if len(reply) < 13 or reply[4:8] != b"\xffSMB" or reply[8] != 0x72:
        return []
    if reply[9:13] != b"\x00\x00\x00\x00":
        return []
    return [info.finding(svc.host, port=svc.port, evidence="Server accepted the NT LM 0.12 (SMBv1) dialect")]


@service_check(
    lambda s: s.port in (139, 445),
    id="NET-SMB-PUBLIC",
    title="Windows file sharing (SMB) reachable from the internet",
    severity="high",
    category="network",
    description="SMB should never be exposed to the internet; it is a prime target for "
    "credential attacks and wormable vulnerabilities.",
    remediation="Block TCP 139/445 at the perimeter firewall and use a VPN for remote access.",
)
async def smb_public(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    if not ctx.public:
        return []
    return [info.finding(svc.host, port=svc.port, evidence=f"TCP {svc.port} open on a public address")]


# --------------------------------------------------------------------- rdp

RDP_NEG_SSL_ONLY = bytes.fromhex("030000130ee000000000000100080001000000")


@service_check(
    lambda s: s.port == 3389 or s.name == "rdp",
    id="NET-RDP-NO-NLA",
    title="Remote Desktop does not require Network Level Authentication",
    severity="high",
    category="network",
    description="Without NLA, the server presents a login session before the user "
    "authenticates, exposing it to brute force and pre-auth vulnerabilities such as "
    "BlueKeep (CVE-2019-0708).",
    remediation="Require NLA: System Properties > Remote > 'Allow connections only from "
    "computers running Remote Desktop with Network Level Authentication'.",
    references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708"],
)
async def rdp_nla(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    reply = await try_exchange(svc.host, svc.port, RDP_NEG_SSL_ONLY, timeout=ctx.timeout)
    if len(reply) < 11 or reply[0] != 0x03:
        return []
    svc.name, svc.product = "rdp", "Remote Desktop"
    if len(reply) >= 19:
        kind = reply[11]
        (value,) = struct.unpack_from("<I", reply, 15)
        if kind == 0x03 and value == 5:  # HYBRID_REQUIRED_BY_SERVER -> NLA enforced
            return []
        if kind == 0x02 and value == 1:
            return [info.finding(svc.host, port=svc.port, evidence="Server accepted TLS without CredSSP (NLA)")]
        if kind == 0x03 and value == 2:
            return [info.finding(svc.host, port=svc.port, severity="critical",
                                 evidence="Server only supports legacy RDP security (no TLS, no NLA)")]  # fmt: skip
        return []
    return [info.finding(svc.host, port=svc.port, severity="critical",
                         evidence="Server did not negotiate security; legacy RDP security only")]  # fmt: skip


@service_check(
    lambda s: s.port == 3389 or s.name == "rdp",
    id="NET-RDP-PUBLIC",
    title="Remote Desktop reachable from the internet",
    severity="high",
    category="network",
    description="Internet-facing RDP is one of the most common initial access vectors for "
    "ransomware operators (credential stuffing and RDP exploits).",
    remediation="Put RDP behind a VPN or RD Gateway with MFA, and block 3389 at the firewall.",
)
async def rdp_public(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    if not ctx.public:
        return []
    return [info.finding(svc.host, port=svc.port, evidence="TCP 3389 open on a public address")]


# --------------------------------------------------------------------- vnc


@service_check(
    lambda s: s.name == "vnc",
    id="NET-VNC-NOAUTH",
    title="VNC server allows access without a password",
    severity="critical",
    category="network",
    description="The VNC server offers the 'None' security type: anyone who connects gets "
    "the desktop session.",
    remediation="Configure a VNC password or stronger authentication, and only expose VNC "
    "over SSH tunnels or a VPN.",
)
async def vnc_noauth(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(svc.host, svc.port), ctx.timeout)
    except (OSError, asyncio.TimeoutError):
        return []
    try:
        hello = await asyncio.wait_for(reader.readexactly(12), ctx.timeout)
        m = re.match(rb"RFB (\d{3})\.(\d{3})\n", hello)
        if not m:
            return []
        major, minor = int(m.group(1)), int(m.group(2))
        if (major, minor) >= (3, 7):
            writer.write(b"RFB 003.008\n" if minor >= 8 else b"RFB 003.007\n")
            await writer.drain()
            count = (await asyncio.wait_for(reader.readexactly(1), ctx.timeout))[0]
            if count == 0:
                return []
            types = await asyncio.wait_for(reader.readexactly(count), ctx.timeout)
            no_auth = 1 in types
        else:
            writer.write(b"RFB 003.003\n")
            await writer.drain()
            (sec,) = struct.unpack(">I", await asyncio.wait_for(reader.readexactly(4), ctx.timeout))
            no_auth = sec == 1
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
        return []
    finally:
        writer.close()
    if not no_auth:
        return []
    return [info.finding(svc.host, port=svc.port, evidence="Security type 'None' offered")]


# --------------------------------------------------------------- databases

DB_NAMES = {"mysql", "postgresql", "mssql", "oracle", "couchdb", "mongodb", "redis", "elasticsearch"}


@service_check(
    lambda s: s.name in DB_NAMES,
    id="NET-DB-PUBLIC",
    title="Database service reachable from the internet",
    severity="high",
    category="network",
    description="Database ports should only be reachable from application servers. Public "
    "exposure invites brute-force attacks and exploitation of database vulnerabilities.",
    remediation="Firewall the port so only trusted application hosts can connect, or bind the "
    "database to a private interface.",
)
async def db_public(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    if not ctx.public:
        return []
    return [info.finding(svc.host, port=svc.port, title=f"{svc.product or svc.name} reachable from the internet",
                         evidence=f"{svc.name} on TCP {svc.port} at a public address")]  # fmt: skip


# --------------------------------------------------------------------- ssh

# Distro packages that carry the regreSSHion (CVE-2024-6387) fix, keyed by the
# upstream version shown in the banner.
_REGRESSHION_FIXED = {
    ("Ubuntu", "8.9p1"): "8.9p1-3ubuntu0.10",
    ("Ubuntu", "9.3p1"): "9.3p1-1ubuntu3.6",
    ("Ubuntu", "9.6p1"): "9.6p1-3ubuntu13.3",
    ("Debian", "9.2p1"): "9.2p1-2+deb12u3",
}
_OPENSSH_RE = re.compile(r"OpenSSH[_-](\d+)\.(\d+)(?:p(\d+))?(?:\s+(Ubuntu|Debian)-(\S+))?")


def openssh_version(banner: str):
    m = _OPENSSH_RE.search(banner)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    return (major, minor, patch), m.group(4), m.group(5)


@service_check(
    lambda s: s.name == "ssh" and s.product == "OpenSSH",
    id="NET-SSH-REGRESSHION",
    title="OpenSSH vulnerable to regreSSHion remote code execution (CVE-2024-6387)",
    severity="high",
    category="network",
    description="A signal-handler race condition in OpenSSH's sshd (8.5p1 through 9.7p1 on "
    "glibc Linux) allows unauthenticated remote code execution as root.",
    remediation="Upgrade OpenSSH to 9.8p1 or your distribution's patched package. As a "
    "stop-gap, set LoginGraceTime 0 in sshd_config.",
    references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
)
async def ssh_regresshion(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    parsed = openssh_version(svc.banner)
    if not parsed:
        return []
    ver, distro, revision = parsed
    if not ((8, 5, 1) <= ver < (9, 8, 1) or ver < (4, 4, 1)):
        return []
    upstream = f"{ver[0]}.{ver[1]}p{ver[2]}"
    confidence = "likely"
    evidence = f"Banner: {svc.banner}"
    if distro:
        fixed = _REGRESSHION_FIXED.get((distro, upstream))
        if fixed and revision:
            if compare_dpkg(f"{upstream}-{revision}", fixed) >= 0:
                return []  # distro backported the fix
            evidence += f" (fixed in {distro} package {fixed})"
        else:
            confidence = "potential"
            evidence += " - distro packages may carry a backported fix; run a credentialed scan to confirm"
    return [info.finding(svc.host, port=svc.port, cves=["CVE-2024-6387"], confidence=confidence,
                         evidence=evidence)]  # fmt: skip


# ----------------------------------------------------------- banner checks

_BANNER_VULNS = [
    (
        "ftp",
        re.compile(r"vsFTPd 2\.3\.4\b"),
        "NET-FTP-VSFTPD-BACKDOOR",
        "vsftpd 2.3.4 backdoored release",
        "critical",
        ["CVE-2011-2523"],
        "This vsftpd build contains a backdoor that opens a root shell on port 6200.",
    ),
    (
        "ftp",
        re.compile(r"ProFTPD 1\.3\.5(?![a-z\d])"),
        "NET-FTP-PROFTPD-MODCOPY",
        "ProFTPD 1.3.5 mod_copy arbitrary file copy",
        "critical",
        ["CVE-2015-3306"],
        "mod_copy lets unauthenticated users copy arbitrary files, leading to code execution.",
    ),
    (
        "smtp",
        re.compile(r"Exim 4\.(8[7-9]|9[01])\b"),
        "NET-SMTP-EXIM-RCE",
        "Exim remote command execution (CVE-2019-10149)",
        "critical",
        ["CVE-2019-10149"],
        "Exim 4.87 to 4.91 allow remote command execution via crafted recipient addresses.",
    ),
]


def _make_banner_check(svc_name, pattern, cid, title, severity, cves, description):
    @service_check(
        lambda s, _n=svc_name: s.name == _n,
        id=cid,
        title=title,
        severity=severity,
        category="network",
        description=description,
        remediation="Upgrade to a supported, patched release.",
        references=[f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves],
    )
    async def _check(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
        if not pattern.search(svc.banner):
            return []
        return [info.finding(svc.host, port=svc.port, cves=list(cves), confidence="likely",
                             evidence=f"Banner: {svc.banner}")]  # fmt: skip

    return _check


for _spec in _BANNER_VULNS:
    _make_banner_check(*_spec)


# -------------------------------------------------------------------- snmp

SNMP_GET_SYSDESCR_PUBLIC = bytes.fromhex(
    "302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500"
)


def _snmp_probe(host: str, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(SNMP_GET_SYSDESCR_PUBLIC, (host, 161))
            data, _ = sock.recvfrom(4096)
            return data
        except OSError:
            return b""


def _snmp_sysdescr(data: bytes) -> str:
    oid = bytes.fromhex("2b06010201010100")
    idx = data.find(oid)
    if idx < 0:
        return ""
    pos = idx + len(oid)
    if pos + 2 <= len(data) and data[pos] == 0x04:
        length = data[pos + 1]
        start = pos + 2
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[start : start + n], "big")
            start += n
        return data[start : start + length].decode("utf-8", "replace")
    return ""


@host_network_check(
    id="NET-SNMP-PUBLIC",
    title="SNMP responds to the default 'public' community",
    severity="high",
    category="network",
    description="SNMP with the default community string discloses detailed system, network "
    "and process information, and write access (if enabled) allows reconfiguration.",
    remediation="Change the community string, restrict SNMP by source address, or move to "
    "SNMPv3 with authentication and encryption.",
)
async def snmp_public(info: CheckInfo, host: str, services: list[Service], ctx: CheckContext) -> list[Finding]:
    data = await asyncio.to_thread(_snmp_probe, host, ctx.timeout)
    if not data or data[0] != 0x30:
        return []
    descr = _snmp_sysdescr(data)
    services.append(Service(host=host, port=161, proto="udp", name="snmp", banner=descr[:200]))
    return [info.finding(host, port=161, evidence=f"sysDescr: {descr[:160]}" if descr else "Community 'public' accepted")]
