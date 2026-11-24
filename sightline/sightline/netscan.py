"""Asynchronous TCP discovery, port scanning and service fingerprinting.

Uses plain TCP connect() scans, so it needs no root privileges or raw sockets.
A refused connection still proves the host is up, which lets us detect live
hosts that block ping.
"""

from __future__ import annotations

import asyncio
import re
import ssl
import struct
from dataclasses import dataclass, field

from sightline.models import Service

# Ports chosen for exposure value: remote admin, databases, caches, file
# sharing, container/orchestration APIs, mail, and common web ports.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1883, 2049, 2181, 2375,
    2376, 2379, 3000, 3128, 3306, 3389, 4369, 4848, 5000, 5432, 5601, 5672, 5900,
    5901, 5984, 5985, 5986, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8086, 8088,
    8443, 8500, 8888, 9000, 9090, 9092, 9100, 9200, 9300, 9443, 10250, 11211,
    15672, 27017, 50000,
]  # fmt: skip

WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    2379: "etcd", 3306: "mysql", 3389: "rdp", 4369: "epmd", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 5901: "vnc", 5984: "couchdb", 5985: "winrm",
    5986: "winrm-tls", 6379: "redis", 6443: "kubernetes", 9092: "kafka",
    9200: "elasticsearch", 10250: "kubelet", 11211: "memcached", 27017: "mongodb",
}  # fmt: skip


def parse_ports(spec: str | None) -> list[int]:
    if not spec or spec == "default":
        return list(DEFAULT_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "default":
            ports.update(DEFAULT_PORTS)
        elif "-" in part:
            lo, hi = part.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if not (1 <= lo_i <= hi_i <= 65535):
                raise ValueError(f"invalid port range {part!r}")
            ports.update(range(lo_i, hi_i + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"invalid port {p}")
            ports.add(p)
    return sorted(ports)


def insecure_tls_context() -> ssl.SSLContext:
    """A client context that accepts any certificate - we are inspecting, not trusting."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


@dataclass
class PortState:
    open: list[int] = field(default_factory=list)
    alive: bool = False


async def _probe_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore):
    async with sem:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except ConnectionRefusedError:
            return port, "closed"
        except (asyncio.TimeoutError, OSError):
            return port, "filtered"
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (asyncio.TimeoutError, OSError):
            pass
        return port, "open"


async def scan_ports(
    host: str, ports: list[int], timeout: float = 1.0, sem: asyncio.Semaphore | None = None
) -> PortState:
    sem = sem or asyncio.Semaphore(256)
    results = await asyncio.gather(*(_probe_port(host, p, timeout, sem) for p in ports))
    state = PortState()
    for port, status in results:
        if status == "open":
            state.open.append(port)
            state.alive = True
        elif status == "closed":
            state.alive = True  # an RST means something answered
    state.open.sort()
    return state


# ------------------------------------------------------------ connections


async def exchange(
    host: str,
    port: int,
    payload: bytes | None = None,
    *,
    tls: bool = False,
    timeout: float = 3.0,
    read_bytes: int = 4096,
    read_all: bool = False,
) -> bytes:
    """Connect, optionally send a payload, and read the reply (b'' on silence)."""
    ctx = insecure_tls_context() if tls else None
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout)
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        data = b""
        try:
            while len(data) < read_bytes:
                chunk = await asyncio.wait_for(reader.read(read_bytes - len(data)), timeout)
                if not chunk:
                    break
                data += chunk
                if not read_all:
                    break
        except asyncio.TimeoutError:
            pass
        return data
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (asyncio.TimeoutError, OSError, ssl.SSLError):
            pass


async def try_exchange(*args, **kwargs) -> bytes:
    try:
        return await exchange(*args, **kwargs)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, EOFError):
        return b""


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: str
    raw_head: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def parse_http(raw: bytes) -> HttpResponse | None:
    if not raw.startswith(b"HTTP/"):
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip().lower()
            headers[key] = (headers[key] + ", " if key in headers else "") + v.strip()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    return HttpResponse(status, headers, body.decode("utf-8", "replace"), lines[0])


def _dechunk(body: bytes) -> bytes:
    out = b""
    while body:
        size_line, _, rest = body.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            return out + body
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2 :]
    return out


async def http_get(
    host: str,
    port: int,
    path: str = "/",
    *,
    tls: bool = False,
    timeout: float = 4.0,
    vhost: str | None = None,
    max_bytes: int = 65536,
    method: str = "GET",
) -> HttpResponse | None:
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {vhost or host}\r\n"
        "User-Agent: Mozilla/5.0 (compatible; Sightline vulnerability scanner)\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    raw = await try_exchange(
        host, port, request, tls=tls, timeout=timeout, read_bytes=max_bytes, read_all=True
    )
    return parse_http(raw)


# ----------------------------------------------------------- fingerprints

_BANNER_RULES: list[tuple[str, re.Pattern, str]] = [
    ("ssh", re.compile(r"^SSH-[\d.]+-OpenSSH[_-]([\w.]+)"), "OpenSSH"),
    ("ssh", re.compile(r"^SSH-[\d.]+-dropbear[_-]?([\w.]*)", re.I), "Dropbear"),
    ("ssh", re.compile(r"^SSH-[\d.]+-(\S+)"), ""),
    ("ftp", re.compile(r"^220.*vsFTPd ([\d.]+)", re.I), "vsftpd"),
    ("ftp", re.compile(r"^220.*ProFTPD ([\d.]+\w*)", re.I), "ProFTPD"),
    ("ftp", re.compile(r"^220.*Pure-FTPd", re.I), "Pure-FTPd"),
    ("ftp", re.compile(r"^220.*FileZilla Server(?: version)? ?([\d.]+)?", re.I), "FileZilla"),
    ("smtp", re.compile(r"^220.*Postfix", re.I), "Postfix"),
    ("smtp", re.compile(r"^220.*Exim ([\d.]+)", re.I), "Exim"),
    ("smtp", re.compile(r"^220.*Microsoft ESMTP", re.I), "Microsoft Exchange"),
    ("smtp", re.compile(r"^220.*E?SMTP", re.I), ""),
    ("ftp", re.compile(r"^220[ -]"), ""),
    ("pop3", re.compile(r"^\+OK"), ""),
    ("imap", re.compile(r"^\* OK.*IMAP", re.I), ""),
    ("vnc", re.compile(r"^RFB (\d{3}\.\d{3})"), "VNC"),
    ("redis", re.compile(r"^-(?:NOAUTH|ERR)"), "Redis"),
]

_HTTP_SERVER_RE = re.compile(r"^([A-Za-z][\w .-]*?)(?:/([\w.-]+))?(?:\s|$)")


def _mysql_greeting(data: bytes) -> str | None:
    if len(data) > 6 and data[4] == 10:
        end = data.find(b"\x00", 5)
        if end > 5:
            return data[5:end].decode("ascii", "replace")
    return None


async def _protocol_nudge(svc: Service, timeout: float) -> bool:
    """Identify well-known binary protocols directly. Returns True if identified."""
    host, port = svc.host, svc.port
    if port == 6379:
        reply = await try_exchange(host, port, b"PING\r\n", timeout=timeout)
        if reply.startswith((b"+PONG", b"-NOAUTH", b"-ERR", b"-DENIED")):
            svc.name, svc.product = "redis", "Redis"
            svc.banner = reply.decode("latin-1", "replace").strip()[:120]
            return True
    elif port == 11211:
        reply = await try_exchange(host, port, b"version\r\n", timeout=timeout)
        if reply.startswith(b"VERSION"):
            svc.name, svc.product = "memcached", "memcached"
            parts = reply.split()
            svc.version = parts[1].decode("ascii", "replace") if len(parts) > 1 else ""
            return True
    return False


# Ports where the client speaks first, so waiting for a greeting only wastes time.
CLIENT_FIRST_PORTS = {
    80, 81, 443, 591, 2375, 2376, 3000, 5000, 5601, 5984, 5985, 5986, 6443, 7001, 8000,
    8008, 8080, 8081, 8086, 8088, 8443, 8500, 8888, 9000, 9090, 9200, 9443, 10250, 15672,
}  # fmt: skip
TLS_PORTS = {443, 465, 636, 993, 995, 2376, 5986, 6443, 8443, 9443, 10250}


async def _greeting_stage(svc: Service, timeout: float) -> bool:
    """Servers that talk first: SSH, FTP, SMTP, POP/IMAP, MySQL, VNC, telnet."""
    greeting = await try_exchange(svc.host, svc.port, None, timeout=timeout)
    if not greeting:
        return False
    text = greeting.decode("latin-1", "replace").strip()
    svc.banner = text.splitlines()[0][:200] if text else ""
    version = _mysql_greeting(greeting)
    if version:
        svc.name, svc.product = "mysql", "MariaDB" if "mariadb" in version.lower() else "MySQL"
        svc.version = version.split("-")[0]
        svc.banner = f"MySQL protocol, version {version}"
        return True
    if greeting[:1] == b"\xff":  # telnet IAC option negotiation
        svc.name, svc.banner = "telnet", "telnet negotiation"
        return True
    for name, rx, product in _BANNER_RULES:
        m = rx.search(svc.banner)
        if m:
            svc.name = name
            svc.product = product or (m.group(1) if m.groups() else "")
            if product and m.groups() and m.group(1):
                svc.version = m.group(1)
            return True
    if svc.port == 23 or b"login:" in greeting.lower():
        svc.name = "telnet"
    return True


async def _tls_stage(svc: Service, timeout: float) -> bool:
    request = b"GET / HTTP/1.0\r\nHost: " + svc.host.encode() + b"\r\n\r\n"
    reply = await try_exchange(svc.host, svc.port, request, tls=True, timeout=timeout)
    if reply:
        svc.tls = True
        resp = parse_http(reply)
        if resp:
            svc.name = "https"
            _http_details(svc, resp)
        elif svc.name in ("unknown", "http"):
            svc.name = "tls"
        return True
    if svc.port in TLS_PORTS and await _tls_handshake_ok(svc.host, svc.port, timeout):
        # Some TLS servers send nothing back for a bare HTTP/1.0 request.
        svc.tls = True
        if svc.name == "unknown":
            svc.name = "tls"
        return True
    return False


async def _http_stage(svc: Service, timeout: float) -> bool:
    resp = await http_get(svc.host, svc.port, "/", timeout=timeout, max_bytes=16384)
    if not resp:
        return False
    svc.name = "http"
    _http_details(svc, resp)
    return True


async def fingerprint(host: str, port: int, timeout: float = 3.0) -> Service:
    svc = Service(host=host, port=port, name=WELL_KNOWN.get(port, "unknown"))
    if await _protocol_nudge(svc, timeout):
        return svc
    greeting_wait = min(timeout, 2.0)
    if port in CLIENT_FIRST_PORTS:
        stages = [(_tls_stage, timeout), (_http_stage, timeout), (_greeting_stage, greeting_wait)]
    else:
        stages = [(_greeting_stage, greeting_wait), (_tls_stage, timeout), (_http_stage, timeout)]
    for stage, wait in stages:
        if await stage(svc, wait):
            return svc
    return svc


async def _tls_handshake_ok(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=insecure_tls_context()),
            timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False
    writer.close()
    return True


def _http_details(svc: Service, resp: HttpResponse) -> None:
    server = resp.header("server")
    svc.banner = (resp.raw_head + (f" | Server: {server}" if server else ""))[:200]
    if server:
        m = _HTTP_SERVER_RE.match(server)
        if m:
            svc.product = m.group(1).strip()
            svc.version = m.group(2) or ""
    body = resp.body
    if "trying to access MongoDB over HTTP" in body:
        svc.name, svc.product = "mongodb", "MongoDB"
        return
    if '"tagline" : "You Know, for Search"' in body or '"cluster_name"' in body:
        svc.product = "Elasticsearch"
        svc.name = "elasticsearch"
    elif "Docker" in server or '"ApiVersion"' in body:
        svc.product = "Docker Engine API"
    elif resp.header("x-jenkins"):
        svc.product, svc.version = "Jenkins", resp.header("x-jenkins")


# ---------------------------------------------------------------- helpers


def u32le(n: int) -> bytes:
    return struct.pack("<I", n)
