import asyncio
import http.client
import json
import shutil
import ssl
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer

import pytest
from conftest import osv

from sightline import checks
from sightline.checks import CheckContext
from sightline.checks.x509 import parse_certificate
from sightline.cli import main
from sightline.models import Finding, HostResult, ScanResult, Service
from sightline.report.common import patch_plan
from sightline.report.export import to_csv
from sightline.report.html import render_html
from sightline.risk import prioritize
from sightline.storage import ScanStore, apply_diff

HAVE_OPENSSL = shutil.which("openssl") is not None


def make_cert(tmp_path, days=10, bits=1024, digest="sha1", cn="intranet.local"):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", f"rsa:{bits}", "-keyout", str(key), "-out", str(crt),
         "-days", str(days), "-nodes", "-subj", f"/CN={cn}", f"-{digest}",
         "-addext", f"subjectAltName=DNS:{cn},IP:127.0.0.1"],
        check=True, capture_output=True,
    )  # fmt: skip
    return key, crt


@pytest.mark.skipif(not HAVE_OPENSSL, reason="openssl CLI not available")
def test_x509_parser(tmp_path):
    _, crt = make_cert(tmp_path)
    cert = parse_certificate(ssl.PEM_cert_to_DER_cert(crt.read_text()))
    assert cert.subject_cn == "intranet.local" and cert.self_signed
    assert (cert.key_type, cert.key_bits) == ("RSA", 1024)
    assert cert.weak_signature == "sha1WithRSAEncryption"
    assert cert.matches_host("intranet.local") and cert.matches_host("127.0.0.1")
    assert not cert.matches_host("other.local")


@pytest.mark.skipif(not HAVE_OPENSSL, reason="openssl CLI not available")
def test_tls_checks_against_live_server(tmp_path):
    key, crt = make_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(crt, key)

    async def handler(r, w):
        try:
            await asyncio.wait_for(r.read(100), 1)
        except Exception:  # noqa: BLE001
            pass
        w.close()

    async def go():
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        svc = Service(host="127.0.0.1", port=port, name="https", tls=True)
        cctx = CheckContext(timeout=2, hostname="wrong.example")
        found = []
        for reg in checks.by_kind("service"):
            if reg.info.id.startswith("TLS-") and reg.applies(svc):
                found += await reg.func(reg.info, svc, cctx)
        server.close()
        return {f.check_id for f in found}

    ids = asyncio.run(go())
    assert {"TLS-CERT-EXPIRING", "TLS-SELF-SIGNED", "TLS-WEAK-KEY", "TLS-WEAK-SIGNATURE",
            "TLS-HOSTNAME-MISMATCH"} <= ids  # fmt: skip
    assert "TLS-CERT-EXPIRED" not in ids


# ------------------------------------------------------------ risk & history


def _finding(**kw):
    base = dict(check_id="PKG-VULN", title="t", severity="high", host="10.0.0.1", category="package")
    base.update(kw)
    return Finding(**base)


def test_prioritize_ordering():
    fs = [
        _finding(title="low unfixed", severity="low"),
        _finding(title="kev", severity="medium", kev=True, fixed_version="2"),
        _finding(title="net crit", severity="critical", category="network", check_id="NET-X"),
        _finding(title="high fixed", severity="high", fixed_version="2", epss=0.01),
    ]
    prioritize(fs)
    assert [f.title for f in fs][:2] == ["net crit", "kev"] or fs[0].priority == "fix-now"
    assert {f.title: f.priority for f in fs}["kev"] == "fix-now"
    assert {f.title: f.priority for f in fs}["low unfixed"] == "monitor"


def _scan(scan_id, started, findings, hosts=("10.0.0.1",), cred=True):
    return ScanResult(
        scan_id=scan_id, name="office", targets=["10.0.0.0/24"], started=started,
        hosts=[HostResult(address=h, alive=True, credentialed=cred) for h in hosts], findings=findings,
    )  # fmt: skip


def test_diff_new_and_fixed(tmp_path):
    store = ScanStore(tmp_path / "s.sqlite")
    a = _finding(title="a", advisory="A", fixed_version="2")
    b = _finding(title="b", advisory="B", fixed_version="2")
    c = _finding(title="c", advisory="C", fixed_version="2")
    first = _scan("s1", "2026-01-01T00:00:00", [a, b])
    apply_diff(first, store.previous(first))
    store.save(first)
    second = _scan("s2", "2026-01-02T00:00:00", [_finding(title="b", advisory="B", fixed_version="2"), c])
    apply_diff(second, store.previous(second))
    assert second.previous_scan_id == "s1"
    assert {f.advisory: f.status for f in second.findings} == {"B": "existing", "C": "new"}
    assert [f.advisory for f in second.fixed] == ["A"]
    # A host that was not credentialed this time must not have its package findings "fixed"
    third = _scan("s3", "2026-01-03T00:00:00", [], cred=False)
    apply_diff(third, second)
    assert third.fixed == []


def test_patch_plan_and_exports():
    fs = [
        _finding(package="openssl", binaries=["libssl3", "openssl"], fixed_version="3.0.2-1.15", risk=80, priority="fix-now"),
        _finding(package="openssl", binaries=["openssl"], fixed_version="3.0.2-1.14", risk=50, priority="fix-soon"),
        _finding(package="curl", binaries=["curl", "libcurl4"], fixed_version="7.81-1.16", risk=40, priority="plan"),
        _finding(package="tar", fixed_version=None, risk=20, priority="monitor"),
    ]  # fmt: skip
    result = _scan("s1", "2026-01-01T00:00:00", fs)
    result.hosts[0].package_format = "deb"
    plans = patch_plan(result)
    assert len(plans) == 1 and plans[0].findings_resolved == 3
    assert plans[0].command.endswith("--only-upgrade curl libcurl4 libssl3 openssl")
    assert plans[0].items[0].fixed_version == "3.0.2-1.15"
    html = render_html(result)
    assert "<script" in html and "3.0.2-1.15" in html and "</script><script" not in html.replace("<\\/", "")
    assert to_csv(result).count("\n") == 5


def test_html_escapes_script_injection():
    evil = _finding(title="</script><script>alert(1)</script>", category="network", check_id="X")
    html = render_html(_scan("s1", "2026-01-01T00:00:00", [evil]))
    assert "</script><script>alert(1)" not in html


# ----------------------------------------------------------------------- cli


def test_cli_local_scan_end_to_end(tmp_path, capsys, isolated_home):
    """Credentialed local scan with a seeded advisory DB, then history/show/report/diff."""
    from sightline.collect.inventory import COLLECTOR_SCRIPT, parse_collection
    from sightline.collect.runner import LocalRunner
    from sightline.config import vulndb_path
    from sightline.vulndb.store import VulnDB

    inv = parse_collection(LocalRunner().run_script(COLLECTOR_SCRIPT).stdout)
    key = inv.osv_key()
    if not key or not inv.packages:
        pytest.skip("local OS not supported for package matching")
    family, release = key
    eco = {"ubuntu": f"Ubuntu:{release}:LTS", "debian": f"Debian:{release}", "alpine": f"Alpine:v{release}",
           "rocky": f"Rocky Linux:{release}", "almalinux": f"AlmaLinux:{release}",
           "redhat": f"Red Hat:enterprise_linux:{release}::baseos"}[family]  # fmt: skip
    pkg = inv.packages[0]
    db = VulnDB(vulndb_path())
    db.import_records([osv("TEST-CVE-2099-0001", eco, pkg.source_name or pkg.name, [{"introduced": "0"}],
                           severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])])  # fmt: skip
    db.close()

    html = tmp_path / "r.html"
    rc = main(["scan", "--local", "--no-network", "--offline", "--html", str(html), "--fail-on", "critical"])
    out = capsys.readouterr()
    assert rc == 2, out.err  # the seeded critical finding trips --fail-on
    assert "credentialed" in out.out
    assert html.exists() and "TEST-CVE-2099-0001" in html.read_text()

    assert main(["scan", "--local", "--no-network", "--offline", "-q"]) == 0
    assert main(["history"]) == 0
    assert "SCAN ID" in capsys.readouterr().out
    assert main(["diff"]) == 0
    assert "new: 0" in capsys.readouterr().out
    assert main(["report", "latest", "--json", str(tmp_path / "r.json")]) == 0
    assert json.loads((tmp_path / "r.json").read_text())["summary"]["hosts_credentialed"] == 1
    assert main(["checks"]) == 0
    assert "NET-REDIS-NOAUTH" in capsys.readouterr().out
    assert main(["db", "status"]) == 0


def test_ssh_runner_uses_system_ssh(tmp_path, monkeypatch):
    """A fake `ssh` on PATH proves the argv and the single-session script delivery."""
    from sightline.collect.inventory import COLLECTOR_SCRIPT, parse_collection
    from sightline.collect.runner import SSHRunner

    fake = tmp_path / "ssh"
    log = tmp_path / "argv"
    fake.write_text(f'#!/bin/bash\nprintf "%s\\n" "$@" > {log}\nexec sh -s\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    runner = SSHRunner(host="web01", user="ops", port=2222, key="/keys/id", sudo=False)
    inv = parse_collection(runner.run_script(COLLECTOR_SCRIPT).stdout)
    argv = log.read_text().split("\n")
    assert "BatchMode=yes" in argv and "ops@web01" in argv and "2222" in argv and "/keys/id" in argv
    assert argv[-2] == "sh -s"
    assert inv.os_release  # the script really ran


# ----------------------------------------------------------------------- web


@pytest.fixture()
def web_server():
    from sightline.web.server import Handler

    Handler.token, Handler.loopback_only = None, True
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def _req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    return resp.status, resp.read().decode()


def test_web_dashboard_and_api(web_server):
    status, body = _req(web_server, "GET", "/")
    assert status == 200 and "Sightline" in body
    assert _req(web_server, "GET", "/api/scans")[0] == 200
    # CSRF protection: no custom header -> rejected
    status, _ = _req(web_server, "POST", "/api/scans", json.dumps({"local": True}),
                     {"Content-Type": "application/json"})  # fmt: skip
    assert status == 403
    # DNS rebinding protection: foreign Host header -> rejected
    assert _req(web_server, "GET", "/", headers={"Host": "evil.example"})[0] == 401
    # Validation errors are reported
    status, body = _req(web_server, "POST", "/api/scans", json.dumps({"targets": ""}),
                        {"Content-Type": "application/json", "X-Sightline": "1"})  # fmt: skip
    assert status == 400 and "target" in body
    # A real job runs to completion
    status, body = _req(web_server, "POST", "/api/scans",
                        json.dumps({"targets": "127.0.0.1", "ports": "1", "local": False}),
                        {"Content-Type": "application/json", "X-Sightline": "1"})  # fmt: skip
    assert status == 202
    for _ in range(100):
        jobs = json.loads(_req(web_server, "GET", "/api/jobs")[1])
        if jobs and jobs[0]["status"] != "running":
            break
        time.sleep(0.1)
    assert jobs[0]["status"] == "done", jobs[0]
    scan_id = jobs[0]["scan_id"]
    assert _req(web_server, "GET", f"/scans/{scan_id}")[0] == 200
    assert _req(web_server, "DELETE", f"/api/scans/{scan_id}", headers={"X-Sightline": "1"})[0] == 200


def test_web_token_required():
    from sightline.web.server import Handler

    Handler.token, Handler.loopback_only = "s3cret", False
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        assert _req(port, "GET", "/api/scans")[0] == 401
        assert _req(port, "GET", "/api/scans?token=s3cret")[0] == 200
        assert _req(port, "GET", "/api/scans", headers={"Authorization": "Bearer s3cret"})[0] == 200
    finally:
        httpd.shutdown()
        Handler.token, Handler.loopback_only = None, True


def test_web_settings_and_help(web_server):
    # settings GET returns defaults; POST updates them (CSRF header required)
    status, body = _req(web_server, "GET", "/api/settings")
    assert status == 200 and json.loads(body)["org_name"] == "Sightline"
    status, _ = _req(web_server, "POST", "/api/settings", json.dumps({"org_name": "Acme", "accent": "teal"}),
                     {"Content-Type": "application/json"})  # fmt: skip
    assert status == 403  # no X-Sightline header -> CSRF blocked
    status, body = _req(web_server, "POST", "/api/settings", json.dumps({"org_name": "Acme", "accent": "teal"}),
                        {"Content-Type": "application/json", "X-Sightline": "1"})  # fmt: skip
    assert status == 200 and json.loads(body)["org_name"] == "Acme"
    assert json.loads(_req(web_server, "GET", "/api/settings")[1])["accent"] == "#0d9488"
    help_data = json.loads(_req(web_server, "GET", "/api/help")[1])
    assert "glossary" in help_data and "KEV" in help_data["glossary"]
