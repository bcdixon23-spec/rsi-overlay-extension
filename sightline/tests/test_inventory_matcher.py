from datetime import date

from conftest import FIXTURES, osv

from sightline import checks
from sightline.checks import host as host_checks
from sightline.collect.inventory import parse_collection
from sightline.risk import mark_exposure, prioritize
from sightline.vulndb.matcher import enrich, evaluate_range, match_inventory
from sightline.vulndb.store import VulnDB, parse_ecosystem
from sightline.vulndb.versions import compare_dpkg


def load(name):
    return parse_collection((FIXTURES / "collect" / name).read_text())


# ----------------------------------------------------------------- inventory


def test_parse_ubuntu_inventory():
    inv = load("ubuntu2204.txt")
    assert inv.os_name == "Ubuntu 22.04.4 LTS"
    assert inv.osv_key() == ("ubuntu", "22.04")
    assert inv.kernel == "5.15.0-91-generic"
    assert inv.hostname == "web01"
    names = {p.name for p in inv.packages}
    assert "libssl3" in names  # multiarch suffix stripped
    assert "oldpkg" not in names  # removed (rc) packages ignored
    ssl = next(p for p in inv.packages if p.name == "libssl3")
    assert ssl.source_name == "openssl" and ssl.format == "deb"
    listening = {(s.address, s.port, s.process) for s in inv.listening}
    assert ("0.0.0.0", 6379, "redis-server") in listening
    assert ("127.0.0.53", 53, "systemd-resolve") in listening


def test_parse_rocky_inventory():
    inv = load("rocky9.txt")
    assert inv.osv_key() == ("rocky", "9")
    pkgs = {p.name: p for p in inv.packages}
    assert "gpg-pubkey" not in pkgs
    assert pkgs["openssl-libs"].version == "1:3.0.7-24.el9"
    assert pkgs["openssl-libs"].source_name == "openssl"
    assert pkgs["bash"].version == "0:5.1.8-6.el9_1"
    assert inv.listening[0].port == 22 and inv.listening[0].process == "sshd"


def test_parse_alpine_inventory():
    inv = load("alpine319.txt")
    assert inv.osv_key() == ("alpine", "3.19")
    pkgs = {p.name: p for p in inv.packages}
    assert pkgs["libcrypto3"].source_name == "openssl"
    assert pkgs["busybox"].version == "1.36.1-r15"


def test_derivative_distro_mapping():
    mint = parse_collection(
        "@@SL:os-release@@\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"21.3\"\n"
        "UBUNTU_CODENAME=jammy\n@@SL:end@@\n"
    )
    assert mint.osv_key() == ("ubuntu", "22.04")
    centos = parse_collection("@@SL:os-release@@\nID=centos\nVERSION_ID=7\n@@SL:end@@\n")
    assert centos.osv_key() is None


# ---------------------------------------------------------------- ecosystems


def test_parse_ecosystem():
    assert parse_ecosystem("Ubuntu:22.04:LTS") == ("ubuntu", "22.04", "")
    assert parse_ecosystem("Ubuntu:Pro:18.04:LTS") == ("ubuntu", "18.04", "pro")
    assert parse_ecosystem("Ubuntu:24.10") == ("ubuntu", "24.10", "")
    assert parse_ecosystem("Ubuntu:Pro:FIPS:22.04:LTS") is None
    assert parse_ecosystem("Debian:12") == ("debian", "12", "")
    assert parse_ecosystem("Alpine:v3.19") == ("alpine", "3.19", "")
    assert parse_ecosystem("Rocky Linux:9") == ("rocky", "9", "")
    assert parse_ecosystem("AlmaLinux:8") == ("almalinux", "8", "")
    assert parse_ecosystem("Red Hat:enterprise_linux:9::appstream") == ("redhat", "9", "")
    assert parse_ecosystem("Red Hat:rhel_eus:9.2::baseos") is None
    assert parse_ecosystem("PyPI") is None
    assert parse_ecosystem("Debian") is None


def test_evaluate_range():
    events = [{"introduced": "0"}, {"fixed": "1.5-1"}, {"introduced": "2.0-1"}, {"fixed": "2.3-1"}]
    assert evaluate_range(compare_dpkg, "1.0-1", events) == (True, "1.5-1")
    assert evaluate_range(compare_dpkg, "1.5-1", events) == (False, None)
    assert evaluate_range(compare_dpkg, "2.1-1", events) == (True, "2.3-1")
    assert evaluate_range(compare_dpkg, "2.3-1", events) == (False, None)
    assert evaluate_range(compare_dpkg, "9.0", [{"introduced": "0"}]) == (True, None)
    last = [{"introduced": "1.0"}, {"last_affected": "1.4"}]
    assert evaluate_range(compare_dpkg, "1.4", last) == (True, None)
    assert evaluate_range(compare_dpkg, "1.5", last) == (False, None)
    assert evaluate_range(compare_dpkg, "0.9", last) == (False, None)


# ------------------------------------------------------------------ matching

UBUNTU_RECORDS = [
    # Fixed in a newer package: affected, upgrade available
    osv("UBUNTU-CVE-2099-1001", "Ubuntu:22.04:LTS", "openssl",
        [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.15"}],
        severity=[{"type": "Ubuntu", "score": "high"},
                  {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"}],
        summary="openssl denial of service"),
    # A bulletin that repeats CVE-1001 and adds CVE-1002: only 1002 should remain
    osv("USN-9999-1", "Ubuntu:22.04:LTS", "openssl",
        [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.15"}],
        related=["CVE-2099-1001", "CVE-2099-1002"], summary="OpenSSL vulnerabilities"),
    # Already fixed in the installed version
    osv("UBUNTU-CVE-2099-2001", "Ubuntu:22.04:LTS", "curl",
        [{"introduced": "0"}, {"fixed": "7.81.0-1ubuntu1.10"}]),
    # No fix released yet
    osv("UBUNTU-CVE-2099-3001", "Ubuntu:22.04:LTS", "tar", [{"introduced": "0"}],
        severity=[{"type": "Ubuntu", "score": "medium"}]),
    # Fix only through Ubuntu Pro
    osv("UBUNTU-CVE-2099-4001", "Ubuntu:Pro:22.04:LTS", "git",
        [{"introduced": "0"}, {"fixed": "1:2.34.1-1ubuntu1.11+esm1"}],
        severity=[{"type": "Ubuntu", "score": "low"}]),
    # The epoch on openssh must be respected
    osv("UBUNTU-CVE-2099-5001", "Ubuntu:22.04:LTS", "openssh",
        [{"introduced": "0"}, {"fixed": "1:8.9p1-3ubuntu0.10"}],
        severity=[{"type": "Ubuntu", "score": "high"}]),
    # Different release: must not match a 22.04 host
    osv("UBUNTU-CVE-2099-6001", "Ubuntu:24.04:LTS", "openssl",
        [{"introduced": "0"}, {"fixed": "9.9"}]),
    # Different distro: must not match
    osv("DEBIAN-CVE-2099-7001", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "9.9"}]),
    # Withdrawn records are ignored
    dict(osv("UBUNTU-CVE-2099-8001", "Ubuntu:22.04:LTS", "openssl", [{"introduced": "0"}]),
         withdrawn="2099-01-01T00:00:00Z"),
]  # fmt: skip


def _db(tmp_path, records):
    db = VulnDB(tmp_path / "v.sqlite")
    assert db.import_records(records) > 0
    return db


def test_match_ubuntu(tmp_path):
    db = _db(tmp_path, UBUNTU_RECORDS)
    db.import_kev({"vulnerabilities": [{"cveID": "CVE-2099-1002", "dateAdded": "2099-02-01",
                                        "knownRansomwareCampaignUse": "Known"}]})  # fmt: skip
    db.import_epss_csv(["#model", "cve,epss,percentile", "CVE-2099-1001,0.42,0.97"])
    inv = load("ubuntu2204.txt")
    findings, notes = match_inventory(db, inv, "10.0.0.5")
    enrich(db, findings)
    assert notes == []
    by_adv = {f.advisory: f for f in findings}
    assert set(by_adv) == {"UBUNTU-CVE-2099-1001", "USN-9999-1", "UBUNTU-CVE-2099-3001",
                           "UBUNTU-CVE-2099-4001", "UBUNTU-CVE-2099-5001"}  # fmt: skip

    ossl = by_adv["UBUNTU-CVE-2099-1001"]
    assert ossl.package == "openssl"
    assert ossl.binaries == ["libssl3", "openssl"]
    assert ossl.fixed_version == "3.0.2-0ubuntu1.15"
    assert ossl.severity == "high" and ossl.cvss == 9.1
    assert ossl.epss == 0.42
    assert "apt-get install --only-upgrade libssl3 openssl" in ossl.remediation

    usn = by_adv["USN-9999-1"]
    assert usn.cves == ["CVE-2099-1002"]  # CVE-1001 already reported
    assert usn.kev and "ransomware" in usn.evidence

    assert by_adv["UBUNTU-CVE-2099-3001"].fixed_version is None
    assert "Ubuntu Pro" in by_adv["UBUNTU-CVE-2099-4001"].remediation
    assert by_adv["UBUNTU-CVE-2099-5001"].installed_version == "1:8.9p1-3ubuntu0.6"

    mark_exposure(findings, inv)
    assert by_adv["UBUNTU-CVE-2099-5001"].exposed  # sshd listens on 0.0.0.0
    assert by_adv["UBUNTU-CVE-2099-1001"].exposed  # TLS library + network daemon
    assert not by_adv["UBUNTU-CVE-2099-3001"].exposed

    prioritize(findings)
    assert usn.priority == "fix-now"  # known exploited with a fix available
    assert by_adv["UBUNTU-CVE-2099-3001"].priority in ("plan", "monitor")  # no fix yet
    assert findings[0].risk >= findings[-1].risk


def test_match_reports_missing_data(tmp_path):
    db = VulnDB(tmp_path / "v.sqlite")
    findings, notes = match_inventory(db, load("ubuntu2204.txt"), "h")
    assert findings == [] and "sightline db update ubuntu" in notes[0]


def test_match_rocky_epoch_and_binary_names(tmp_path):
    records = [
        # Alma/Rocky advisories often name binary packages and omit the epoch
        osv("RLSA-2099:0001", "Rocky Linux:9", "openssl-libs",
            [{"introduced": "0"}, {"fixed": "3.0.7-25.el9_3"}], aliases=["CVE-2099-9001"],
            db_specific={"severity": "Important"}),
        osv("RLSA-2099:0002", "Rocky Linux:9", "bash",
            [{"introduced": "0"}, {"fixed": "5.1.8-6.el9_1"}], aliases=["CVE-2099-9002"]),
    ]  # fmt: skip
    db = _db(tmp_path, records)
    findings, _ = match_inventory(db, load("rocky9.txt"), "10.0.0.9")
    assert [f.advisory for f in findings] == ["RLSA-2099:0001"]
    f = findings[0]
    assert f.severity == "high" and f.cves == ["CVE-2099-9001"]
    assert "dnf upgrade openssl-libs" in f.remediation


def test_match_alpine_origin_names(tmp_path):
    records = [osv("ALPINE-CVE-2099-0101", "Alpine:v3.19", "openssl",
                   [{"introduced": "0"}, {"fixed": "3.1.4-r6"}])]  # fmt: skip
    db = _db(tmp_path, records)
    findings, _ = match_inventory(db, load("alpine319.txt"), "10.0.0.10")
    assert len(findings) == 1
    assert findings[0].binaries == ["libcrypto3", "libssl3"]
    assert "apk upgrade libcrypto3 libssl3" in findings[0].remediation


def test_import_filters(tmp_path):
    db = VulnDB(tmp_path / "v.sqlite")
    n = db.import_records(UBUNTU_RECORDS, releases={("ubuntu", "24.04")})
    assert n == 1
    assert db.releases() == [("ubuntu", "24.04", 1)]


# ---------------------------------------------------------------- host checks


def _host_findings(inv):
    out = []
    for reg in checks.by_kind("host-config"):
        out += reg.func(reg.info, inv, "10.0.0.5")
    return {f.check_id: f for f in out}


def test_host_config_checks_ubuntu():
    found = _host_findings(load("ubuntu2204.txt"))
    for cid in [
        "HOST-REBOOT-REQUIRED", "HOST-SSH-ROOT-LOGIN", "HOST-SSH-PASSWORD-AUTH", "HOST-UID0-ACCOUNT",
        "HOST-EMPTY-PASSWORD", "HOST-SENSITIVE-FILE-PERMS", "HOST-SUDO-NOPASSWD", "HOST-NO-AUTO-UPDATES",
        "HOST-NO-FIREWALL", "HOST-ASLR-DISABLED", "HOST-DATASTORE-ALL-INTERFACES",
    ]:  # fmt: skip
        assert cid in found, cid
    assert "HOST-SSH-EMPTY-PASSWORDS" not in found
    assert "toor" in found["HOST-UID0-ACCOUNT"].evidence
    assert "5.15.0-97-generic" in found["HOST-REBOOT-REQUIRED"].evidence
    assert "Redis on 0.0.0.0:6379" in found["HOST-DATASTORE-ALL-INTERFACES"].evidence
    assert "world-readable" in found["HOST-SENSITIVE-FILE-PERMS"].evidence


def test_host_config_checks_rocky_sshd_config_file():
    found = _host_findings(load("rocky9.txt"))
    # PermitRootLogin no; PasswordAuthentication unset outside the Match block -> default yes
    assert "HOST-SSH-ROOT-LOGIN" not in found
    assert "HOST-SSH-PASSWORD-AUTH" in found
    assert "HOST-NO-FIREWALL" not in found  # not root: unknown, not reported


def test_eol_os():
    reg = next(r for r in checks.by_kind("host-config") if r.info.id == "HOST-EOL-OS")
    inv = load("ubuntu2204.txt")
    assert host_checks.eol_os(reg.info, inv, "h", today=date(2026, 1, 1)) == []
    soon = host_checks.eol_os(reg.info, inv, "h", today=date(2027, 1, 1))
    assert soon and soon[0].severity == "medium"
    past = host_checks.eol_os(reg.info, inv, "h", today=date(2027, 6, 1))
    assert past and past[0].severity == "high" and "Ubuntu Pro" in past[0].evidence
