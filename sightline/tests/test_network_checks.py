"""Network checks against fake protocol servers on localhost."""

import asyncio
import json
import struct

import pytest

from sightline import checks
from sightline.checks import CheckContext
from sightline.checks.network import bson_decode, openssh_version
from sightline.models import Service
from sightline.netscan import fingerprint, parse_ports, scan_ports


def reg(check_id):
    return next(r for r in checks.load_all() if r.info.id == check_id)


async def with_server(handler, fn):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        return await fn(port)
    finally:
        server.close()
        await server.wait_closed()


def run_check(check_id, handler, name="unknown", port_override=None, **svc_kw):
    async def go(port):
        svc = Service(host="127.0.0.1", port=port_override or port, name=name, **svc_kw)
        if port_override:
            svc.port = port  # connect to the fake, but let applies() see the real port
        r = reg(check_id)
        return await r.func(r.info, svc, CheckContext(timeout=2))

    return asyncio.run(with_server(handler, go))


def bson(obj):
    def enc(doc):
        body = b""
        for k, v in doc.items():
            key = k.encode() + b"\x00"
            if isinstance(v, bool):
                body += b"\x08" + key + (b"\x01" if v else b"\x00")
            elif isinstance(v, float):
                body += b"\x01" + key + struct.pack("<d", v)
            elif isinstance(v, int):
                body += b"\x10" + key + struct.pack("<i", v)
            elif isinstance(v, str):
                s = v.encode() + b"\x00"
                body += b"\x02" + key + struct.pack("<i", len(s)) + s
            elif isinstance(v, list):
                body += b"\x04" + key + enc({str(i): x for i, x in enumerate(v)})
            elif isinstance(v, dict):
                body += b"\x03" + key + enc(v)
        return struct.pack("<i", len(body) + 5) + body + b"\x00"

    return enc(obj)


def op_msg(doc):
    payload = struct.pack("<I", 0) + b"\x00" + bson(doc)
    return struct.pack("<iiii", 16 + len(payload), 99, 1, 2013) + payload


# ------------------------------------------------------------------- tests


def test_parse_ports():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert 6379 in parse_ports("default")
    with pytest.raises(ValueError):
        parse_ports("0-5")


def test_scan_ports_open_and_closed():
    async def handler(r, w):
        w.close()

    async def go(port):
        return await scan_ports("127.0.0.1", [port, 1], timeout=1)

    state = asyncio.run(with_server(handler, go))
    assert state.alive and len(state.open) == 1


def test_fingerprint_ssh_mysql_http():
    async def ssh(r, w):
        w.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        await w.drain()
        w.close()

    async def mysql(r, w):
        w.write(b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00\x08\x00\x00\x00")
        await w.drain()
        w.close()

    async def http(r, w):
        await r.readuntil(b"\r\n\r\n")
        w.write(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Length: 2\r\n\r\nok")
        await w.drain()
        w.close()

    svc = asyncio.run(with_server(ssh, lambda p: fingerprint("127.0.0.1", p, 2)))
    assert (svc.name, svc.product, svc.version) == ("ssh", "OpenSSH", "8.9p1")
    svc = asyncio.run(with_server(mysql, lambda p: fingerprint("127.0.0.1", p, 2)))
    assert (svc.name, svc.product, svc.version) == ("mysql", "MySQL", "8.0.36")
    svc = asyncio.run(with_server(http, lambda p: fingerprint("127.0.0.1", p, 2)))
    assert (svc.name, svc.product, svc.version) == ("http", "nginx", "1.18.0")


def test_redis_noauth_and_auth():
    async def open_redis(r, w):
        await r.readline()
        body = b"# Server\r\nredis_version:7.2.4\r\n"
        w.write(b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
        await w.drain()
        w.close()

    async def auth_redis(r, w):
        await r.readline()
        w.write(b"-NOAUTH Authentication required.\r\n")
        await w.drain()
        w.close()

    found = run_check("NET-REDIS-NOAUTH", open_redis, name="redis")
    assert found and "7.2.4" in found[0].evidence and found[0].severity == "critical"
    assert run_check("NET-REDIS-NOAUTH", auth_redis, name="redis") == []


def test_mongodb_noauth_and_auth():
    def handler(reply_doc):
        async def h(r, w):
            header = await r.readexactly(16)
            (length,) = struct.unpack_from("<i", header)
            await r.readexactly(length - 16)
            w.write(op_msg(reply_doc))
            await w.drain()
            w.close()

        return h

    open_doc = {"databases": [{"name": "admin"}, {"name": "shop"}], "ok": 1.0}
    found = run_check("NET-MONGODB-NOAUTH", handler(open_doc), name="mongodb")
    assert found and "shop" in found[0].evidence
    locked = {"ok": 0.0, "errmsg": "command listDatabases requires authentication", "code": 13}
    assert run_check("NET-MONGODB-NOAUTH", handler(locked), name="mongodb") == []


def test_bson_roundtrip():
    doc = bson({"a": 1, "b": "x", "c": [1, 2], "d": {"e": True}, "f": 2.5})
    assert bson_decode(doc) == {"a": 1, "b": "x", "c": [1, 2], "d": {"e": True}, "f": 2.5}


def test_vnc_no_auth():
    def handler(types):
        async def h(r, w):
            w.write(b"RFB 003.008\n")
            await w.drain()
            await r.readexactly(12)
            w.write(bytes([len(types)]) + bytes(types))
            await w.drain()
            await asyncio.sleep(0.05)
            w.close()

        return h

    assert run_check("NET-VNC-NOAUTH", handler([1, 2]), name="vnc")
    assert run_check("NET-VNC-NOAUTH", handler([2]), name="vnc") == []


def test_rdp_nla_detection():
    def handler(reply_hex):
        async def h(r, w):
            await r.readexactly(19)
            w.write(bytes.fromhex(reply_hex))
            await w.drain()
            w.close()

        return h

    no_nla = "030000130ed00000123400" + "0200080001000000"
    nla = "030000130ed00000123400" + "0300080005000000"
    found = run_check("NET-RDP-NO-NLA", handler(no_nla), name="rdp")
    assert found and "without CredSSP" in found[0].evidence
    assert run_check("NET-RDP-NO-NLA", handler(nla), name="rdp") == []


def test_smb1_detection():
    async def smb1(r, w):
        await r.read(100)
        w.write(b"\x00\x00\x00\x25\xffSMB\x72\x00\x00\x00\x00" + b"\x00" * 28)
        await w.drain()
        w.close()

    async def smb2_only(r, w):
        await r.read(100)
        w.close()

    assert run_check("NET-SMB1", smb1, port_override=445)
    assert run_check("NET-SMB1", smb2_only, port_override=445) == []


def test_ftp_anonymous_and_cleartext():
    async def ftp(r, w):
        w.write(b"220-Welcome\r\n220 (vsFTPd 3.0.5)\r\n")
        await w.drain()
        while line := await r.readline():
            cmd = line.decode().split()[0].upper()
            reply = {"USER": b"331 Please specify the password.\r\n", "PASS": b"230 Login successful.\r\n",
                     "AUTH": b"530 Please login with USER and PASS.\r\n"}.get(cmd, b"500 ?\r\n")  # fmt: skip
            w.write(reply)
            await w.drain()
        w.close()

    assert run_check("NET-FTP-ANON", ftp, name="ftp")
    assert run_check("NET-FTP-CLEARTEXT", ftp, name="ftp")


def http_handler(routes, server="TestServer/1.0"):
    async def h(r, w):
        head = (await r.readuntil(b"\r\n\r\n")).decode()
        path = head.split()[1]
        status, body = routes.get(path, (404, "not found"))
        body = body.encode()
        w.write(f"HTTP/1.1 {status} X\r\nServer: {server}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
        await w.drain()
        w.close()

    return h


def test_web_exposure_checks():
    routes = {
        "/.git/HEAD": (200, "ref: refs/heads/main\n"),
        "/.env": (200, "APP_ENV=prod\nDB_PASSWORD=hunter2\nSTRIPE_SECRET_KEY=sk_live_x\n"),
        "/": (200, "<html><title>Index of /</title></html>"),
        "/actuator/env": (200, '{"activeProfiles":[],"propertySources":[]}'),
        "/server-status": (200, "<h1>Apache Server Status for host</h1>"),
    }
    for cid in ("WEB-GIT-EXPOSED", "WEB-ENV-EXPOSED", "WEB-DIR-LISTING", "WEB-ACTUATOR-ENV", "WEB-SERVER-STATUS"):
        assert run_check(cid, http_handler(routes), name="http"), cid
    # A site that answers everything with its HTML home page must not trigger .env/.git
    spa = {p: (200, "<!doctype html><html>app</html>") for p in ("/.git/HEAD", "/.env", "/")}
    for cid in ("WEB-GIT-EXPOSED", "WEB-ENV-EXPOSED", "WEB-DIR-LISTING"):
        assert run_check(cid, http_handler(spa), name="http") == [], cid


def test_apache_banner_and_basic_auth():
    found = run_check("WEB-APACHE-TRAVERSAL", http_handler({"/": (200, "hi")}, "Apache/2.4.49 (Unix)"), name="http")
    assert found and found[0].kev and "CVE-2021-41773" in found[0].cves

    async def basic(r, w):
        await r.readuntil(b"\r\n\r\n")
        w.write(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="admin"\r\nContent-Length: 0\r\n\r\n')
        await w.drain()
        w.close()

    assert run_check("WEB-BASIC-AUTH-CLEARTEXT", basic, name="http")


def test_docker_and_elastic_apis():
    docker = http_handler({"/version": (200, json.dumps({"ApiVersion": "1.43", "Version": "24.0.7"}))})
    found = run_check("NET-DOCKER-API", docker, name="http", product="Docker Engine API")
    assert found and "24.0.7" in found[0].evidence
    es = http_handler({"/": (200, '{"cluster_name":"prod","version":{"number":"8.11.1"},'
                                  '"tagline" : "You Know, for Search"}')})  # fmt: skip
    found = run_check("NET-ELASTIC-NOAUTH", es, name="http", product="Elasticsearch")
    assert found and "8.11.1" in found[0].evidence


def test_regresshion_banner_logic():
    assert openssh_version("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3")[0] == (9, 6, 1)

    def check(banner):
        r = reg("NET-SSH-REGRESSHION")
        svc = Service(host="127.0.0.1", port=22, name="ssh", product="OpenSSH", banner=banner)
        return asyncio.run(r.func(r.info, svc, CheckContext()))

    assert check("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")[0].confidence == "likely"
    assert check("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10") == []  # backported fix
    assert check("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3") == []
    assert check("SSH-2.0-OpenSSH_9.0p1 Debian-1+b2")[0].confidence == "potential"
    assert check("SSH-2.0-OpenSSH_9.7p1")[0].confidence == "likely"
    assert check("SSH-2.0-OpenSSH_9.8p1") == []
    assert check("SSH-2.0-OpenSSH_8.4p1") == []


def test_public_exposure_checks_only_fire_on_public_addresses():
    r = reg("NET-RDP-PUBLIC")
    svc = Service(host="203.0.113.5", port=3389, name="rdp")
    assert asyncio.run(r.func(r.info, svc, CheckContext(public=False))) == []
    assert asyncio.run(r.func(r.info, svc, CheckContext(public=True)))
