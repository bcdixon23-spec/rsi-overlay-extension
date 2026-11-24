"""Turn a stream of decoded packets into security findings and a traffic picture.

This is the opinionated layer that a plain packet capture does not give you:
instead of millions of frames, it surfaces the things that matter for security
- credentials crossing the wire in cleartext, plaintext protocols carrying
sessions, and a passive inventory of the hosts and services actually talking.
All of it is passive: Sightline only reads frames, it never injects any.
"""

from __future__ import annotations

import base64
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sightline.capture import decode as dec
from sightline.models import Finding, HostResult, ScanResult, Service

PLAINTEXT_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 512: "rexec", 513: "rlogin", 514: "rsh", 1521: "Oracle TNS",
    3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP", 11211: "memcached",
}  # fmt: skip
PASSWORD_FIELDS = re.compile(rb"(?i)(?:^|&)(password|passwd|pwd|pass|user_pass|j_password)=([^&\s]{1,64})")
_PRINTABLE = re.compile(rb"[^\x20-\x7e]")


@dataclass
class HostInfo:
    ip: str
    mac: str = ""
    hostnames: set[str] = field(default_factory=set)
    services: dict[int, str] = field(default_factory=dict)  # port -> proto name
    client_ports: set[int] = field(default_factory=set)
    bytes_sent: int = 0
    bytes_recv: int = 0
    protocols: set[str] = field(default_factory=set)


class Analyzer:
    def __init__(self):
        self.hosts: dict[str, HostInfo] = {}
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()
        self.proto_bytes: dict[str, int] = defaultdict(int)
        self.conversations: dict[tuple, int] = defaultdict(int)
        self.dns_queries: dict[str, int] = defaultdict(int)
        self.tls_sni: dict[str, int] = defaultdict(int)
        self.http_hosts: set[str] = set()
        self._ftp_users: dict[tuple, str] = {}
        self._frames = 0
        self._bytes = 0
        self._first_ts = 0.0
        self._last_ts = 0.0

    # --------------------------------------------------------------- intake

    def feed(self, pkt: dec.Decoded) -> None:
        self._frames += 1
        self._bytes += pkt.orig_len
        if pkt.ts:
            self._first_ts = pkt.ts if not self._first_ts else min(self._first_ts, pkt.ts)
            self._last_ts = max(self._last_ts, pkt.ts)
        if pkt.proto:
            self.proto_bytes[pkt.proto] += pkt.orig_len
        self._record_hosts(pkt)
        if pkt.arp:
            return
        if pkt.proto in ("tcp", "udp"):
            self.conversations[pkt.flow_key()] += pkt.orig_len
            self._discover_services(pkt)
            self._inspect_app(pkt)

    def _host(self, ip: str) -> HostInfo | None:
        if not ip or ip in ("0.0.0.0", "::"):
            return None
        if ip not in self.hosts:
            self.hosts[ip] = HostInfo(ip=ip)
        return self.hosts[ip]

    def _record_hosts(self, pkt: dec.Decoded) -> None:
        src = self._host(pkt.src)
        dst = self._host(pkt.dst)
        if src:
            src.bytes_sent += pkt.orig_len
            if pkt.eth_src and pkt.eth_src != "00:00:00:00:00:00":
                src.mac = pkt.eth_src
            if pkt.proto:
                src.protocols.add(pkt.proto)
        if dst:
            dst.bytes_recv += pkt.orig_len
        if pkt.arp and pkt.arp["op"] == "reply":
            h = self._host(pkt.arp["sender_ip"])
            if h:
                h.mac = pkt.arp["sender_mac"]

    def _discover_services(self, pkt: dec.Decoded) -> None:
        # A SYN-ACK identifies the server side and its listening port.
        if pkt.proto == "tcp" and pkt.flags & dec.SYN and pkt.flags & dec.ACK:
            srv = self._host(pkt.src)
            if srv and pkt.sport:
                srv.services.setdefault(pkt.sport, "tcp")
        # An application-layer response also identifies a server.
        if pkt.app.get("http", {}).get("kind") == "response":
            srv = self._host(pkt.src)
            if srv and pkt.sport:
                srv.services.setdefault(pkt.sport, "http")
        if pkt.app.get("dns", {}).get("response"):
            srv = self._host(pkt.src)
            if srv and pkt.sport == 53:
                srv.services.setdefault(53, "dns")

    # ----------------------------------------------------------- app checks

    def _inspect_app(self, pkt: dec.Decoded) -> None:
        app = pkt.app
        if "dns" in app:
            self._dns(app["dns"], pkt)
        if "dhcp" in app:
            self._dhcp(app["dhcp"], pkt)
        if "tls" in app:
            sni = app["tls"].get("sni")
            if sni:
                self.tls_sni[sni] += 1
                h = self._host(pkt.dst)
                if h and pkt.dport:
                    h.services.setdefault(pkt.dport, "tls")
                    h.hostnames.add(sni)
        if "http" in app:
            self._http(app["http"], pkt)
        if pkt.proto == "tcp":
            self._cleartext_login(pkt)
            self._plaintext_proto(pkt)
        if pkt.proto == "udp" and (pkt.dport == 161 or pkt.sport == 161):
            self._snmp(pkt)

    def _dns(self, dns: dict, pkt: dec.Decoded) -> None:
        for q in dns.get("questions", []):
            self.dns_queries[q["name"]] += 1
        for a in dns.get("answers", []):
            if a["type"] in ("A", "AAAA") and a["value"]:
                h = self._host(a["value"])
                if h:
                    h.hostnames.add(a["name"])

    def _dhcp(self, dhcp: dict, pkt: dec.Decoded) -> None:
        host = dhcp.get("hostname")
        ip = dhcp.get("requested_ip") or (pkt.src if pkt.src != "0.0.0.0" else "")
        if host and ip:
            h = self._host(ip)
            if h:
                h.hostnames.add(host)

    def _http(self, http: dict, pkt: dec.Decoded) -> None:
        headers = http.get("headers", {})
        if http.get("kind") == "request":
            host = headers.get("host", "")
            if host:
                self.http_hosts.add(host.split(":")[0])
            auth = headers.get("authorization", "")
            if auth.lower().startswith("basic "):
                creds = _decode_basic(auth)
                if creds:
                    target = pkt.dst + (f" (Host: {host})" if host else "")
                    self._credential(pkt, "HTTP Basic auth", creds[0], creds[1], target, pkt.dst)
            body = http.get("body", b"")
            if http.get("method") == "POST" and body:
                m = PASSWORD_FIELDS.search(body if isinstance(body, bytes) else body.encode())
                if m:
                    user = _form_user(body)
                    self._http_password(pkt, http.get("path", "/"), user)

    def _cleartext_login(self, pkt: dec.Decoded) -> None:
        payload = pkt.payload
        if not payload or len(payload) > 4096:
            return
        dp = pkt.dport or 0
        try:
            text = payload.decode("latin-1")
        except ValueError:
            return
        key = pkt.flow_key()
        if dp == 21 or pkt.sport == 21:  # FTP control
            for line in text.split("\r\n"):
                up = line.upper()
                if up.startswith("USER "):
                    self._ftp_users[key] = line[5:].strip()
                elif up.startswith("PASS "):
                    user = self._ftp_users.get(key, "?")
                    self._credential(pkt, "FTP", user, line[5:].strip(), pkt.dst)
        elif dp == 110:  # POP3
            for line in text.split("\r\n"):
                if line.upper().startswith("USER "):
                    self._ftp_users[key] = line[5:].strip()
                elif line.upper().startswith("PASS "):
                    self._credential(pkt, "POP3", self._ftp_users.get(key, "?"), line[5:].strip(), pkt.dst)
        elif dp == 143 and "LOGIN " in text.upper():  # IMAP
            m = re.search(r'(?i)\bLOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?', text)
            if m:
                self._credential(pkt, "IMAP", m.group(1), m.group(2), pkt.dst)
        elif dp == 25 or dp == 587:  # SMTP AUTH
            self._smtp_auth(text, pkt)

    def _smtp_auth(self, text: str, pkt: dec.Decoded) -> None:
        for line in text.split("\r\n"):
            up = line.upper()
            if up.startswith("AUTH PLAIN ") and len(line) > 11:
                decoded = _b64(line[11:].strip())
                if decoded and decoded.count("\x00") >= 1:
                    parts = decoded.split("\x00")
                    self._credential(pkt, "SMTP AUTH PLAIN", parts[-2] or parts[0], parts[-1], pkt.dst)
            elif up.startswith("AUTH LOGIN") and len(line) > 11:
                user = _b64(line[11:].strip())
                if user:
                    self._ftp_users[pkt.flow_key()] = user

    def _plaintext_proto(self, pkt: dec.Decoded) -> None:
        if not pkt.payload:
            return
        for port in (pkt.dport, pkt.sport):
            name = PLAINTEXT_PORTS.get(port or 0)
            if name:
                server_ip = pkt.dst if port == pkt.dport else pkt.src
                server_port = port
                if name == "Telnet":
                    self._telnet(pkt, server_ip, server_port)
                else:
                    self._note_plaintext(name, server_ip, server_port, pkt)
                return

    def _telnet(self, pkt: dec.Decoded, ip: str, port: int) -> None:
        key = ("SNIFF-TELNET", ip, port)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            check_id="SNIFF-TELNET", title="Telnet session observed in cleartext", severity="high",
            host=ip, category="network", port=port, confidence="confirmed",
            description="A Telnet session was captured on the network. Telnet transmits everything, "
            "including the login and password, in cleartext.",
            evidence=f"Live Telnet traffic to {ip}:{port}",
            remediation="Replace Telnet with SSH and block TCP 23.",
        ))  # fmt: skip

    def _note_plaintext(self, name: str, ip: str, port: int, pkt: dec.Decoded) -> None:
        key = ("SNIFF-PLAINTEXT-PROTO", ip, port, name)
        if key in self._seen:
            return
        self._seen.add(key)
        sev = "medium" if name in ("HTTP", "SNMP", "LDAP") else "medium"
        self.findings.append(Finding(
            check_id="SNIFF-PLAINTEXT-PROTO", title=f"{name} traffic is unencrypted", severity=sev,
            host=ip, category="network", port=port, confidence="confirmed",
            description=f"{name} traffic was seen in cleartext. Anyone on the network path can read "
            "the session contents and any credentials it carries.",
            evidence=f"Unencrypted {name} observed to/from {ip}:{port}",
            remediation=f"Move {name} to its TLS-protected equivalent, or tunnel it over a VPN.",
        ))  # fmt: skip

    def _snmp(self, pkt: dec.Decoded) -> None:
        community = _snmp_community(pkt.payload)
        if community is None:
            return
        ip = pkt.dst if pkt.dport == 161 else pkt.src
        key = ("SNIFF-SNMP-COMMUNITY", ip, community)
        if key in self._seen:
            return
        self._seen.add(key)
        weak = community.lower() in ("public", "private")
        self.findings.append(Finding(
            check_id="SNIFF-SNMP-COMMUNITY", title="SNMP community string sent in cleartext",
            severity="high" if weak else "medium", host=ip, category="network", port=161, confidence="confirmed",
            description="SNMPv1/v2c sends the community string (effectively a password) in cleartext. "
            + ("This one is a well-known default." if weak else ""),
            evidence=f"Community string '{community}' observed to {ip}:161",
            remediation="Use SNMPv3 with authentication and privacy, and change default community strings.",
        ))  # fmt: skip

    def _credential(self, pkt: dec.Decoded, proto: str, user: str, password: str, target: str, host_ip: str = "") -> None:
        user = _clean(user)
        password = _clean(password)
        host_ip = host_ip or _ip_of(target)
        key = ("SNIFF-CLEARTEXT-CREDS", host_ip, proto, user)
        if key in self._seen:
            return
        self._seen.add(key)
        masked = (password[:1] + "*" * max(len(password) - 1, 0)) if password else "(empty)"
        self.findings.append(Finding(
            check_id="SNIFF-CLEARTEXT-CREDS", title=f"Cleartext credentials captured ({proto})", severity="critical",
            host=host_ip, category="network", port=pkt.dport, confidence="confirmed",
            description="Sightline recovered a username and password from unencrypted traffic. Anyone "
            "able to see this traffic (a switch span port, a compromised host, open Wi-Fi) can do the same.",
            evidence=f"{proto}: username '{user}', password '{masked}' to {target}",
            remediation="Stop using the plaintext protocol; switch to a TLS/SSH-protected equivalent and "
            "rotate the exposed credentials immediately.",
        ))  # fmt: skip

    def _http_password(self, pkt: dec.Decoded, path: str, user: str) -> None:
        key = ("SNIFF-HTTP-PASSWORD", pkt.dst, path)
        if key in self._seen:
            return
        self._seen.add(key)
        who = f" (username '{_clean(user)}')" if user else ""
        self.findings.append(Finding(
            check_id="SNIFF-HTTP-PASSWORD", title="Password submitted over unencrypted HTTP", severity="high",
            host=pkt.dst, category="network", port=pkt.dport, confidence="confirmed",
            description="A login form posted a password field over plain HTTP. The password crosses the "
            "network in cleartext on every submission.",
            evidence=f"POST {path} with a password field{who} to {pkt.dst}",
            remediation="Serve the login over HTTPS only and redirect HTTP to HTTPS.",
        ))  # fmt: skip

    # -------------------------------------------------------------- outputs

    def duration(self) -> float:
        return max(self._last_ts - self._first_ts, 0.0)

    def traffic_summary(self) -> dict:
        talkers = sorted(self.hosts.values(), key=lambda h: h.bytes_sent + h.bytes_recv, reverse=True)
        convs = sorted(self.conversations.items(), key=lambda kv: kv[1], reverse=True)
        return {
            "frames": self._frames,
            "bytes": self._bytes,
            "duration": round(self.duration(), 2),
            "hosts": len(self.hosts),
            "protocols": dict(sorted(self.proto_bytes.items(), key=lambda kv: kv[1], reverse=True)),
            "top_talkers": [
                {"host": h.ip, "name": sorted(h.hostnames)[0] if h.hostnames else "",
                 "bytes": h.bytes_sent + h.bytes_recv} for h in talkers[:10]
            ],  # fmt: skip
            "conversations": [
                {"a": f"{k[1][0]}:{k[1][1]}", "b": f"{k[2][0]}:{k[2][1]}", "proto": k[0], "bytes": v}
                for k, v in convs[:10]
            ],
            "dns_queries": sorted(self.dns_queries.items(), key=lambda kv: kv[1], reverse=True)[:15],
            "tls_sni": sorted(self.tls_sni.items(), key=lambda kv: kv[1], reverse=True)[:15],
        }

    def build_result(self, scan_id: str, name: str, source: str) -> ScanResult:
        result = ScanResult(
            scan_id=scan_id, name=name, targets=[source],
            started=datetime.fromtimestamp(self._first_ts or 0, timezone.utc).isoformat(timespec="seconds")
            if self._first_ts else datetime.now(timezone.utc).isoformat(timespec="seconds"),
            finished=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            options={"mode": "passive capture", "source": source},
        )  # fmt: skip
        for ip, info in sorted(self.hosts.items()):
            if not info.services and not info.hostnames and info.bytes_sent + info.bytes_recv < 1:
                continue
            host = HostResult(
                address=ip, hostname=sorted(info.hostnames)[0] if info.hostnames else "", alive=True,
                services=[Service(host=ip, port=p, proto="tcp", name=n) for p, n in sorted(info.services.items())],
                notes=[f"Observed passively ({info.bytes_sent + info.bytes_recv} bytes)"],
            )  # fmt: skip
            result.hosts.append(host)
        result.findings = self.findings
        result.capture = self.traffic_summary()
        return result


# ----------------------------------------------------------------- helpers


def _clean(value: str) -> str:
    value = _PRINTABLE.sub(b"", value.encode("latin-1", "replace")).decode("latin-1")
    return value[:64]


def _ip_of(target: str) -> str:
    return target.split(":")[0].split("/")[0]


def _decode_basic(auth: str) -> tuple[str, str] | None:
    try:
        raw = base64.b64decode(auth.split(" ", 1)[1], validate=True).decode("latin-1")
    except (ValueError, IndexError):
        return None
    if ":" not in raw:
        return None
    user, password = raw.split(":", 1)
    return user, password


def _b64(value: str) -> str:
    try:
        return base64.b64decode(value, validate=True).decode("latin-1")
    except ValueError:
        return ""


def _form_user(body) -> str:
    if isinstance(body, str):
        body = body.encode()
    m = re.search(rb"(?i)(?:^|&)(user(?:name)?|login|email|j_username)=([^&\s]{1,64})", body)
    return m.group(2).decode("latin-1", "replace") if m else ""


_SNMP_COMMUNITY_RE = None


def _snmp_community(payload: bytes) -> str | None:
    """Pull the community string out of an SNMPv1/v2c message (BER)."""
    if len(payload) < 8 or payload[0] != 0x30:
        return None
    try:
        pos = 2 if payload[1] < 0x80 else 2 + (payload[1] & 0x7F)
        if payload[pos] != 0x02:  # version INTEGER
            return None
        vlen = payload[pos + 1]
        version = payload[pos + 2] if vlen == 1 else 0
        if version not in (0, 1):  # v1=0, v2c=1
            return None
        pos += 2 + vlen
        if payload[pos] != 0x04:  # community OCTET STRING
            return None
        clen = payload[pos + 1]
        if clen & 0x80:
            return None
        community = payload[pos + 2 : pos + 2 + clen]
        if community and not _PRINTABLE.search(community):
            return community.decode("latin-1")
    except IndexError:
        return None
    return None
