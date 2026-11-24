"""Risk-based prioritisation.

Severity alone produces a wall of "high" findings. Sightline ranks each
finding on a 0-100 scale using what actually predicts compromise:

  * how bad it is            (CVSS score, or the distro's triaged severity)
  * whether it is exploited  (CISA KEV) or likely to be (EPSS)
  * whether it is reachable  (network-facing service, internet-routable host)
  * whether you can act now  (a fixed package exists; detection confidence)

and sorts it into four buckets: fix-now, fix-soon, plan, monitor.
"""

from __future__ import annotations

from sightline.collect.inventory import Inventory
from sightline.models import Finding

SEVERITY_SCORE = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
    "unknown": 4.0,
}
PRIORITIES = ("fix-now", "fix-soon", "plan", "monitor")
PRIORITY_LABEL = {
    "fix-now": "Fix now",
    "fix-soon": "Fix this week",
    "plan": "Plan a fix",
    "monitor": "Monitor",
}

# Listening process name -> source package name prefixes it belongs to.
PROCESS_PACKAGES = {
    "sshd": ("openssh",),
    "nginx": ("nginx",),
    "apache2": ("apache2",),
    "httpd": ("httpd",),
    "redis-server": ("redis",),
    "redis-serve": ("redis",),
    "mysqld": ("mysql", "mariadb", "percona"),
    "mariadbd": ("mariadb",),
    "postgres": ("postgresql",),
    "postmaster": ("postgresql",),
    "named": ("bind",),
    "smbd": ("samba",),
    "vsftpd": ("vsftpd",),
    "proftpd": ("proftpd",),
    "memcached": ("memcached",),
    "mongod": ("mongodb",),
    "exim4": ("exim4",),
    "exim": ("exim",),
    "master": ("postfix",),
    "dovecot": ("dovecot",),
    "haproxy": ("haproxy",),
    "squid": ("squid",),
    "cupsd": ("cups",),
    "dnsmasq": ("dnsmasq",),
    "rpcbind": ("rpcbind",),
    "chronyd": ("chrony",),
    "ntpd": ("ntp", "ntpsec"),
    "avahi-daemon": ("avahi",),
    "dockerd": ("docker", "moby"),
    "containerd": ("containerd",),
    "node": ("nodejs",),
    "php-fpm": ("php",),
    "java": ("openjdk",),
    "openvpn": ("openvpn",),
    "unbound": ("unbound",),
    "lighttpd": ("lighttpd",),
    "caddy": ("caddy",),
    "xrdp": ("xrdp",),
    "snmpd": ("net-snmp",),
}
# TLS libraries sit directly on the network path of every daemon that uses them.
SHARED_NETWORK_LIBS = ("openssl", "gnutls")


def exposed_packages(inv: Inventory) -> set[str]:
    prefixes: set[str] = set()
    for sock in inv.listening:
        if sock.loopback or not sock.process:
            continue
        name = sock.process.split("/")[-1]
        for key, pkgs in PROCESS_PACKAGES.items():
            if name == key or name.startswith(key + "-") or name.startswith(key):
                prefixes.update(pkgs)
    return prefixes


def mark_exposure(findings: list[Finding], inv: Inventory) -> None:
    prefixes = exposed_packages(inv)
    has_network_daemon = any(not s.loopback for s in inv.listening if s.proto == "tcp")
    for f in findings:
        if f.category != "package" or not f.package:
            continue
        if any(f.package.startswith(p) for p in prefixes):
            f.exposed = True
        elif has_network_daemon and f.package.startswith(SHARED_NETWORK_LIBS):
            f.exposed = True


def score(f: Finding, public: bool = False) -> float:
    label = SEVERITY_SCORE.get(f.severity, SEVERITY_SCORE["unknown"])
    if f.cvss is not None and f.severity != "unknown":
        base = (label + f.cvss) / 2
    elif f.cvss is not None:
        base = f.cvss
    else:
        base = label
    risk = base * 7
    if f.category in ("network", "config") or f.exposed:
        risk += 12
        if public and (f.category == "network" or f.exposed):
            risk += 5
    # Exploit availability. Maturity already folds in KEV ("active"); fall back to
    # the raw KEV flag if exploit intelligence has not run on these findings yet.
    maturity = f.exploit_maturity or ("active" if f.kev else "")
    risk += {"active": 25, "weaponized": 18, "poc": 7}.get(maturity, 0)
    if f.epss:
        risk += min(f.epss, 1.0) * 20
    if f.category == "package" and not f.fixed_version:
        risk *= 0.6
    if f.confidence == "potential":
        risk *= 0.7
    elif f.confidence == "likely":
        risk *= 0.9
    return round(min(risk, 100.0), 1)


def bucket(f: Finding) -> str:
    actionable = f.category != "package" or bool(f.fixed_version)
    if (f.kev or f.exploit_maturity in ("active", "weaponized")) and actionable:
        return "fix-now"
    if f.risk >= 75:
        return "fix-now"
    if f.risk >= 50:
        return "fix-soon"
    if f.risk >= 30:
        return "plan"
    return "monitor"


def prioritize(findings: list[Finding], public_hosts: set[str] | None = None) -> list[Finding]:
    public_hosts = public_hosts or set()
    for f in findings:
        f.risk = score(f, f.host in public_hosts)
        f.priority = bucket(f)
    findings.sort(key=lambda f: (-f.risk, f.host, f.title))
    return findings
