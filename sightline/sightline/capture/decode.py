"""Protocol decoders for captured frames.

Every decoder is defensive: a truncated or malformed packet yields a partial
Decoded object rather than raising, so a capture of real-world junk never stops
the analysis. Layers covered: Ethernet/802.1Q, IPv4, IPv6, TCP, UDP, ICMP,
ICMPv6, ARP, and light application parsing for DNS, DHCP, HTTP and TLS SNI.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from sightline.capture.pcap import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW

ETHERTYPE_IP4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IP6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP6 = 58

PROTO_NAMES = {PROTO_ICMP: "icmp", PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP6: "icmpv6"}

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


@dataclass
class Decoded:
    ts: float = 0.0
    orig_len: int = 0
    eth_src: str = ""
    eth_dst: str = ""
    ethertype: int = 0
    vlan: int | None = None
    src: str = ""
    dst: str = ""
    proto: str = ""
    ttl: int = 0
    sport: int | None = None
    dport: int | None = None
    flags: int = 0
    seq: int = 0
    payload: bytes = b""
    app: dict = field(default_factory=dict)
    arp: dict | None = None

    @property
    def flag_str(self) -> str:
        names = [n for b, n in ((SYN, "S"), (ACK, "A"), (FIN, "F"), (RST, "R"), (PSH, "P"), (URG, "U")) if self.flags & b]
        return "".join(names)

    @property
    def src_port(self) -> str:
        return f"{self.src}:{self.sport}" if self.sport is not None else self.src

    @property
    def dst_port(self) -> str:
        return f"{self.dst}:{self.dport}" if self.dport is not None else self.dst

    def flow_key(self) -> tuple:
        """Bidirectional flow identity (endpoints sorted so both directions match)."""
        a = (self.src, self.sport or 0)
        b = (self.dst, self.dport or 0)
        lo, hi = sorted((a, b))
        return (self.proto, lo, hi)


def mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def decode(data: bytes, ts: float = 0.0, orig_len: int | None = None, linktype: int = LINKTYPE_ETHERNET) -> Decoded:
    pkt = Decoded(ts=ts, orig_len=orig_len if orig_len is not None else len(data))
    try:
        if linktype == LINKTYPE_ETHERNET:
            _ethernet(pkt, data)
        elif linktype == LINKTYPE_LINUX_SLL:
            _linux_sll(pkt, data)
        elif linktype == LINKTYPE_RAW:
            _ip_auto(pkt, data)
        else:
            _ethernet(pkt, data)
    except (struct.error, IndexError, ValueError):
        pass
    return pkt


def _ethernet(pkt: Decoded, data: bytes) -> None:
    if len(data) < 14:
        return
    pkt.eth_dst, pkt.eth_src = mac(data[0:6]), mac(data[6:12])
    etype = struct.unpack("!H", data[12:14])[0]
    off = 14
    if etype == ETHERTYPE_VLAN and len(data) >= 18:
        pkt.vlan = struct.unpack("!H", data[14:16])[0] & 0x0FFF
        etype = struct.unpack("!H", data[16:18])[0]
        off = 18
    pkt.ethertype = etype
    _l3(pkt, data, off, etype)


def _linux_sll(pkt: Decoded, data: bytes) -> None:
    if len(data) < 16:
        return
    etype = struct.unpack("!H", data[14:16])[0]
    pkt.ethertype = etype
    _l3(pkt, data, 16, etype)


def _ip_auto(pkt: Decoded, data: bytes) -> None:
    if not data:
        return
    version = data[0] >> 4
    if version == 4:
        pkt.ethertype = ETHERTYPE_IP4
        _ipv4(pkt, data, 0)
    elif version == 6:
        pkt.ethertype = ETHERTYPE_IP6
        _ipv6(pkt, data, 0)


def _l3(pkt: Decoded, data: bytes, off: int, etype: int) -> None:
    if etype == ETHERTYPE_IP4:
        _ipv4(pkt, data, off)
    elif etype == ETHERTYPE_IP6:
        _ipv6(pkt, data, off)
    elif etype == ETHERTYPE_ARP:
        _arp(pkt, data, off)


def _ipv4(pkt: Decoded, data: bytes, off: int) -> None:
    if len(data) < off + 20:
        return
    ihl = (data[off] & 0x0F) * 4
    total = struct.unpack("!H", data[off + 2 : off + 4])[0]
    pkt.ttl = data[off + 8]
    proto = data[off + 9]
    pkt.proto = PROTO_NAMES.get(proto, str(proto))
    pkt.src = socket.inet_ntoa(data[off + 12 : off + 16])
    pkt.dst = socket.inet_ntoa(data[off + 16 : off + 20])
    l4 = off + ihl
    end = off + total if off + total <= len(data) and total >= ihl else len(data)
    _l4(pkt, data, l4, proto, end)


def _ipv6(pkt: Decoded, data: bytes, off: int) -> None:
    if len(data) < off + 40:
        return
    plen = struct.unpack("!H", data[off + 4 : off + 6])[0]
    nxt = data[off + 6]
    pkt.ttl = data[off + 7]
    pkt.src = socket.inet_ntop(socket.AF_INET6, data[off + 8 : off + 24])
    pkt.dst = socket.inet_ntop(socket.AF_INET6, data[off + 24 : off + 40])
    l4 = off + 40
    end = min(l4 + plen, len(data)) if plen else len(data)
    # Skip a couple of common extension headers to reach the real transport.
    for _ in range(4):
        if nxt in (PROTO_TCP, PROTO_UDP, PROTO_ICMP6) or l4 + 2 > len(data):
            break
        if nxt in (0, 43, 60):  # hop-by-hop, routing, dest options
            ext_len = (data[l4 + 1] + 1) * 8
            nxt = data[l4]
            l4 += ext_len
        else:
            break
    pkt.proto = PROTO_NAMES.get(nxt, str(nxt))
    _l4(pkt, data, l4, nxt, end)


def _arp(pkt: Decoded, data: bytes, off: int) -> None:
    if len(data) < off + 28:
        return
    op = struct.unpack("!H", data[off + 6 : off + 8])[0]
    pkt.proto = "arp"
    pkt.arp = {
        "op": "request" if op == 1 else "reply" if op == 2 else str(op),
        "sender_mac": mac(data[off + 8 : off + 14]),
        "sender_ip": socket.inet_ntoa(data[off + 14 : off + 18]),
        "target_mac": mac(data[off + 18 : off + 24]),
        "target_ip": socket.inet_ntoa(data[off + 24 : off + 28]),
    }
    pkt.src, pkt.dst = pkt.arp["sender_ip"], pkt.arp["target_ip"]


def _l4(pkt: Decoded, data: bytes, off: int, proto: int, end: int) -> None:
    if proto == PROTO_TCP and len(data) >= off + 20:
        pkt.sport, pkt.dport = struct.unpack("!HH", data[off : off + 4])
        pkt.seq = struct.unpack("!I", data[off + 4 : off + 8])[0]
        data_off = ((data[off + 12] >> 4) & 0x0F) * 4
        pkt.flags = data[off + 13]
        payload_start = off + data_off
        pkt.payload = data[payload_start:end] if payload_start < end else b""
        _app(pkt)
    elif proto == PROTO_UDP and len(data) >= off + 8:
        pkt.sport, pkt.dport = struct.unpack("!HH", data[off : off + 4])
        ulen = struct.unpack("!H", data[off + 4 : off + 6])[0]
        payload_end = min(off + ulen, end) if ulen >= 8 else end
        pkt.payload = data[off + 8 : payload_end]
        _app(pkt)
    elif proto in (PROTO_ICMP, PROTO_ICMP6) and len(data) >= off + 4:
        pkt.app["icmp"] = {"type": data[off], "code": data[off + 1]}


# ---------------------------------------------------------------- app layer

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ")


def _app(pkt: Decoded) -> None:
    payload = pkt.payload
    if not payload:
        return
    sp, dp = pkt.sport or 0, pkt.dport or 0
    if pkt.proto == "udp" and 53 in (sp, dp):
        dns = parse_dns(payload)
        if dns:
            pkt.app["dns"] = dns
        return
    if pkt.proto == "udp" and (dp in (67, 68) or sp in (67, 68)):
        dhcp = parse_dhcp(payload)
        if dhcp:
            pkt.app["dhcp"] = dhcp
        return
    if pkt.proto != "tcp":
        return
    if payload.startswith(HTTP_METHODS):
        pkt.app["http"] = parse_http_request(payload)
    elif payload.startswith(b"HTTP/"):
        pkt.app["http"] = parse_http_response(payload)
    elif payload[:1] == b"\x16" and len(payload) > 5 and payload[5:6] == b"\x01":
        tls = parse_tls_client_hello(payload)
        if tls:
            pkt.app["tls"] = tls


def _headers(block: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in block.split(b"\r\n"):
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return headers


def parse_http_request(payload: bytes) -> dict:
    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    out = {"kind": "request", "method": parts[0].decode("latin-1", "replace"),
           "path": parts[1].decode("latin-1", "replace") if len(parts) > 1 else "",
           "headers": _headers(b"\r\n".join(lines[1:]))}  # fmt: skip
    if body:
        out["body"] = body[:2048]
    return out


def parse_http_response(payload: bytes) -> dict:
    head, _, _ = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    status = 0
    if len(parts) > 1 and parts[1].isdigit():
        status = int(parts[1])
    return {"kind": "response", "status": status, "headers": _headers(b"\r\n".join(lines[1:]))}


def _dns_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped = False
    end = off
    while depth < 20:
        if off >= len(data):
            break
        length = data[off]
        if length == 0:
            off += 1
            if not jumped:
                end = off
            break
        if length & 0xC0 == 0xC0:
            if off + 2 > len(data):
                break
            pointer = struct.unpack("!H", data[off : off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off = pointer
            jumped = True
            depth += 1
            continue
        labels.append(data[off + 1 : off + 1 + length].decode("latin-1", "replace"))
        off += 1 + length
        if not jumped:
            end = off
    return ".".join(labels), end


_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


def parse_dns(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    tid, flags, qd, an = struct.unpack("!HHHH", payload[:8])
    off = 12
    questions = []
    for _ in range(min(qd, 8)):
        name, off = _dns_name(payload, off)
        if off + 4 > len(payload):
            break
        qtype = struct.unpack("!H", payload[off : off + 2])[0]
        off += 4
        questions.append({"name": name, "type": _DNS_TYPES.get(qtype, str(qtype))})
    answers = []
    for _ in range(min(an, 16)):
        name, off = _dns_name(payload, off)
        if off + 10 > len(payload):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", payload[off : off + 10])
        off += 10
        rdata = payload[off : off + rdlen]
        value = ""
        if rtype == 1 and rdlen == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == 28 and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (5, 2, 12):
            value, _ = _dns_name(payload, off)
        answers.append({"name": name, "type": _DNS_TYPES.get(rtype, str(rtype)), "value": value})
        off += rdlen
    return {"id": tid, "response": bool(flags & 0x8000), "questions": questions, "answers": answers}


def parse_dhcp(payload: bytes) -> dict | None:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":  # magic cookie
        return None
    out: dict = {"client_mac": mac(payload[28:34])}
    off = 240
    msg_types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
    while off + 2 <= len(payload):
        opt = payload[off]
        if opt == 255:
            break
        if opt == 0:
            off += 1
            continue
        length = payload[off + 1]
        value = payload[off + 2 : off + 2 + length]
        if opt == 53 and value:
            out["type"] = msg_types.get(value[0], str(value[0]))
        elif opt == 12:
            out["hostname"] = value.decode("latin-1", "replace")
        elif opt == 50 and length == 4:
            out["requested_ip"] = socket.inet_ntoa(value)
        elif opt == 60:
            out["vendor"] = value.decode("latin-1", "replace")
        off += 2 + length
    return out


def parse_tls_client_hello(payload: bytes) -> dict | None:
    """Pull the SNI host and offered version out of a TLS ClientHello."""
    try:
        if payload[0] != 0x16:
            return None
        pos = 5  # skip record header
        if payload[pos] != 0x01:  # handshake type ClientHello
            return None
        pos += 4  # handshake type + 3-byte length
        client_version = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2 + 32  # version + random
        sid_len = payload[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2 + cs_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return {"version": _tls_name(client_version)}
        ext_total = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2
        ext_end = min(pos + ext_total, len(payload))
        sni = ""
        alpn = []
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", payload[pos : pos + 4])
            pos += 4
            edata = payload[pos : pos + elen]
            if etype == 0 and len(edata) >= 5:  # server_name
                name_len = struct.unpack("!H", edata[3:5])[0]
                sni = edata[5 : 5 + name_len].decode("latin-1", "replace")
            elif etype == 16 and len(edata) >= 2:  # ALPN
                p = 2
                while p + 1 <= len(edata):
                    ln = edata[p]
                    alpn.append(edata[p + 1 : p + 1 + ln].decode("latin-1", "replace"))
                    p += 1 + ln
            pos += elen
        return {"version": _tls_name(client_version), "sni": sni, "alpn": alpn}
    except (struct.error, IndexError):
        return None


def _tls_name(version: int) -> str:
    return {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(
        version, f"{version:#06x}"
    )
