"""Packet decoding, pcap I/O, capture filtering and traffic analysis."""

import socket
import struct

import pytest

from sightline.capture import decode as D
from sightline.capture.analyze import Analyzer, _snmp_community
from sightline.capture.pcap import PcapError, open_writer, read_frames
from sightline.capture.run import run_pcap
from sightline.capture.sniffer import CaptureFilter


# ----------------------------------------------------------- packet builders


def eth(payload, etype=0x0800, dst=b"\xaa\xaa\xaa\xaa\xaa\xaa", src=b"\xbb\xbb\xbb\xbb\xbb\xbb"):
    return dst + src + struct.pack("!H", etype) + payload


def ip4(payload, proto=6, src="10.0.0.9", dst="10.0.0.1", ttl=64):
    total = 20 + len(payload)
    h = struct.pack("!BBHHHBBH", 0x45, 0, total, 1, 0, ttl, proto, 0)
    return h + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def ip6(payload, nxt=6, src="2001:db8::1", dst="2001:db8::2"):
    h = struct.pack("!IHBB", 6 << 28, len(payload), nxt, 64)
    return h + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload


def tcp(payload, sport, dport, flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 0, 0, 0) + payload


def udp(payload, sport, dport):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name, tid=0x1234):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def client_hello(host):
    sni = host.encode()
    server_name = b"\x00" + struct.pack("!H", len(sni)) + sni
    snlist = struct.pack("!H", len(server_name)) + server_name
    ext = struct.pack("!HH", 0, len(snlist)) + snlist
    exts = struct.pack("!H", len(ext)) + ext
    body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# ------------------------------------------------------------------- decode


def test_decode_tcp_http():
    raw = eth(ip4(tcp(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n", 40000, 80)))
    p = D.decode(raw)
    assert p.proto == "tcp" and p.src == "10.0.0.9" and p.dport == 80
    assert p.flag_str == "AP"
    assert p.app["http"]["method"] == "GET" and p.app["http"]["path"] == "/a"


def test_decode_ipv6_and_vlan():
    p = D.decode(eth(ip6(tcp(b"", 1, 443)), etype=0x86DD))
    assert p.src == "2001:db8::1" and p.proto == "tcp" and p.dport == 443
    vlan = eth(struct.pack("!H", 0x0064) + struct.pack("!H", 0x0800) + ip4(tcp(b"", 2, 22)), etype=0x8100)
    pv = D.decode(vlan)
    assert pv.vlan == 0x64 and pv.dport == 22


def test_decode_dns_tls_arp_dhcp():
    assert D.decode(eth(ip4(udp(dns_query("www.example.com"), 5000, 53), proto=17))).app["dns"]["questions"][0]["name"] == "www.example.com"
    assert D.decode(eth(ip4(tcp(client_hello("secure.site"), 40000, 443)))).app["tls"]["sni"] == "secure.site"
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + b"\xbb" * 6 + socket.inet_aton("10.0.0.1") + b"\x00" * 6 + socket.inet_aton("10.0.0.5")
    ap = D.decode(eth(arp, etype=0x0806))
    assert ap.arp["op"] == "request" and ap.arp["sender_ip"] == "10.0.0.1"
    dhcp = b"\x01\x01\x06\x00" + b"\x00" * 24 + b"\x00" * 192 + b"\x63\x82\x53\x63" + b"\x35\x01\x01\x0c\x04host\xff"
    # fix client mac area length (chaddr at offset 28)
    dhcp = bytearray(b"\x01\x01\x06\x00" + b"\x00" * 232 + b"\x63\x82\x53\x63" + b"\x35\x01\x03\x0c\x04mypc\xff")
    dhcp[28:34] = b"\x11\x22\x33\x44\x55\x66"
    dp = D.decode(eth(ip4(udp(bytes(dhcp), 68, 67), proto=17)))
    assert dp.app["dhcp"]["type"] == "REQUEST" and dp.app["dhcp"]["hostname"] == "mypc"


def test_decode_is_truncation_safe():
    full = eth(ip4(tcp(b"GET / HTTP/1.1\r\n\r\n", 1, 2)))
    for n in range(len(full) + 1):
        D.decode(full[:n])  # must never raise
    for n in range(50):
        D.decode(eth(ip6(udp(dns_query("a.b"), 5, 53), nxt=17), etype=0x86DD)[:n])


# --------------------------------------------------------------------- pcap


def test_pcap_roundtrip(tmp_path):
    path = tmp_path / "c.pcap"
    frames = [eth(ip4(tcp(b"hi", 1, 2))), eth(ip4(udp(b"x", 3, 53), proto=17))]
    w = open_writer(path)
    for i, f in enumerate(frames):
        w.write(1700000000.25 + i, f)
    w.close()
    got = list(read_frames(path))
    assert len(got) == 2 and got[0].data == frames[0] and abs(got[0].ts - 1700000000.25) < 1e-6
    assert got[0].linktype == 1


def test_pcap_rejects_bad_and_pcapng(tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"not a pcap file at all........")
    with pytest.raises(PcapError):
        list(read_frames(bad))
    ng = tmp_path / "x.pcapng"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    with pytest.raises(PcapError, match="pcapng"):
        list(read_frames(ng))


# ------------------------------------------------------------------ filters


def test_capture_filter_parse_and_match():
    f = CaptureFilter.parse("host 10.0.0.5 port 80,443 tcp")
    assert f.hosts == {"10.0.0.5"} and f.ports == {80, 443} and f.protos == {"tcp"}
    yes = D.decode(eth(ip4(tcp(b"", 5000, 443), dst="10.0.0.5")))
    no = D.decode(eth(ip4(tcp(b"", 5000, 22), dst="10.0.0.5")))
    assert f.matches(yes) and not f.matches(no)
    assert CaptureFilter.parse("udp 53").matches(D.decode(eth(ip4(udp(b"", 5, 53), proto=17))))
    assert CaptureFilter.parse(None).matches(yes)  # empty filter matches everything


# ------------------------------------------------------------------ analyze


def test_analyzer_finds_cleartext_credentials():
    a = Analyzer()
    cred = __import__("base64").b64encode(b"admin:secret").decode()
    a.feed(D.decode(eth(ip4(tcp(f"GET /x HTTP/1.1\r\nHost: w\r\nAuthorization: Basic {cred}\r\n\r\n".encode(), 40000, 80), dst="10.0.0.1"))))
    a.feed(D.decode(eth(ip4(tcp(b"USER bob\r\n", 41000, 21), dst="10.0.0.2"))))
    a.feed(D.decode(eth(ip4(tcp(b"PASS p@ss\r\n", 41000, 21), dst="10.0.0.2"))))
    ids = {f.check_id for f in a.findings}
    assert "SNIFF-CLEARTEXT-CREDS" in ids and "SNIFF-PLAINTEXT-PROTO" in ids
    ftp = next(f for f in a.findings if f.check_id == "SNIFF-CLEARTEXT-CREDS" and "FTP" in f.title)
    assert "bob" in ftp.evidence and "p" in ftp.evidence and "p@ss" not in ftp.evidence  # password masked
    http = next(f for f in a.findings if "HTTP Basic" in f.title)
    assert http.host == "10.0.0.1" and http.severity == "critical"


def test_analyzer_snmp_telnet_http_password():
    a = Analyzer()
    snmp = b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
    assert _snmp_community(snmp) == "public"
    a.feed(D.decode(eth(ip4(udp(snmp, 40000, 161), proto=17, dst="10.0.0.4"))))
    a.feed(D.decode(eth(ip4(tcp(b"\xff\xfd\x18login:", 23, 50000, flags=0x18), src="10.0.0.5", dst="10.0.0.9"))))
    a.feed(D.decode(eth(ip4(tcp(b"POST /login HTTP/1.1\r\nHost: a\r\n\r\nuser=jo&password=pw123", 40001, 80), dst="10.0.0.6"))))
    ids = {f.check_id for f in a.findings}
    assert {"SNIFF-SNMP-COMMUNITY", "SNIFF-TELNET", "SNIFF-HTTP-PASSWORD"} <= ids
    snmp_f = next(f for f in a.findings if f.check_id == "SNIFF-SNMP-COMMUNITY")
    assert snmp_f.severity == "high"  # 'public' is a default


def test_analyzer_passive_discovery_and_summary():
    a = Analyzer()
    # SYN-ACK from a server reveals its listening port
    a.feed(D.decode(eth(ip4(tcp(b"", 443, 50000, flags=0x12), src="10.0.0.20", dst="10.0.0.9"))))
    a.feed(D.decode(eth(ip4(udp(dns_query("api.example.com"), 5, 53), proto=17))))
    a.feed(D.decode(eth(ip4(tcp(client_hello("cdn.example.com"), 40000, 443), src="10.0.0.9", dst="10.0.0.30"))))
    assert 443 in a.hosts["10.0.0.20"].services
    summary = a.traffic_summary()
    assert summary["frames"] == 3
    assert any(q[0] == "api.example.com" for q in summary["dns_queries"])
    assert any(s[0] == "cdn.example.com" for s in summary["tls_sni"])


def test_run_pcap_end_to_end(tmp_path):
    path = tmp_path / "creds.pcap"
    cred = __import__("base64").b64encode(b"root:toor").decode()
    w = open_writer(path)
    w.write(1.0, eth(ip4(tcp(f"GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Basic {cred}\r\n\r\n".encode(), 40000, 80), dst="192.0.2.5")))
    w.close()
    result = run_pcap(str(path))
    assert result.capture["frames"] == 1
    assert any(f.check_id == "SNIFF-CLEARTEXT-CREDS" for f in result.findings)
    assert result.findings[0].priority == "fix-now"  # a captured password is urgent
