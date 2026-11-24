"""Configuration checks that run on data collected from a credentialed host."""

from __future__ import annotations

from datetime import date

from sightline.checks import CheckInfo, host_config_check
from sightline.collect.inventory import Inventory
from sightline.models import Finding
from sightline.vulndb.versions import rpmvercmp

# End of standard security support per vendor lifecycle pages.
EOL_DATES: dict[tuple[str, str], str] = {
    ("ubuntu", "14.04"): "2019-04-30", ("ubuntu", "16.04"): "2021-04-30",
    ("ubuntu", "18.04"): "2023-05-31", ("ubuntu", "20.04"): "2025-05-31",
    ("ubuntu", "22.04"): "2027-04-30", ("ubuntu", "24.04"): "2029-04-30",
    ("ubuntu", "26.04"): "2031-04-30", ("ubuntu", "23.04"): "2024-01-25",
    ("ubuntu", "23.10"): "2024-07-11", ("ubuntu", "24.10"): "2025-07-10",
    ("ubuntu", "25.04"): "2026-01-15", ("ubuntu", "25.10"): "2026-07-09",
    ("debian", "8"): "2020-06-30", ("debian", "9"): "2022-06-30",
    ("debian", "10"): "2024-06-30", ("debian", "11"): "2026-08-31",
    ("debian", "12"): "2028-06-30", ("debian", "13"): "2030-06-30",
    ("alpine", "3.15"): "2023-11-01", ("alpine", "3.16"): "2024-05-23",
    ("alpine", "3.17"): "2024-11-22", ("alpine", "3.18"): "2025-05-09",
    ("alpine", "3.19"): "2025-11-01", ("alpine", "3.20"): "2026-04-01",
    ("alpine", "3.21"): "2026-11-01", ("alpine", "3.22"): "2027-05-01",
    ("alpine", "3.23"): "2027-11-01",
    ("centos", "6"): "2020-11-30", ("centos", "7"): "2024-06-30", ("centos", "8"): "2021-12-31",
    ("rhel", "6"): "2020-11-30", ("rhel", "7"): "2024-06-30", ("rhel", "8"): "2029-05-31",
    ("rhel", "9"): "2032-05-31", ("rocky", "8"): "2029-05-31", ("rocky", "9"): "2032-05-31",
    ("almalinux", "8"): "2029-05-31", ("almalinux", "9"): "2032-05-31",
    ("ol", "7"): "2024-12-31", ("ol", "8"): "2029-07-31", ("ol", "9"): "2032-06-30",
    ("amzn", "2"): "2026-06-30", ("amzn", "2023"): "2029-06-30",
}  # fmt: skip


def _release_key(inv: Inventory) -> tuple[str, str]:
    osid, version = inv.os_id, inv.os_version
    if osid in ("ubuntu",):
        return osid, version
    if osid == "alpine":
        return osid, ".".join(version.split(".")[:2])
    return osid, version.split(".")[0]


@host_config_check(
    id="HOST-EOL-OS",
    title="Operating system is past end of life",
    severity="high",
    category="config",
    description="The vendor no longer publishes security updates for this release, so newly "
    "discovered vulnerabilities will never be fixed.",
    remediation="Upgrade to a supported release, or buy extended support (e.g. Ubuntu Pro ESM, "
    "RHEL ELS) while you migrate.",
)
def eol_os(info: CheckInfo, inv: Inventory, host: str, today: date | None = None) -> list[Finding]:
    key = _release_key(inv)
    eol = EOL_DATES.get(key)
    if not eol:
        return []
    today = today or date.today()
    eol_date = date.fromisoformat(eol)
    days = (eol_date - today).days
    if days < 0:
        extra = ""
        if inv.os_id == "ubuntu" and inv.os_version.endswith(".04"):
            extra = " Security fixes continue only through Ubuntu Pro (ESM)."
        return [info.finding(host, evidence=f"{inv.os_name}: standard support ended {eol}.{extra}")]
    if days <= 180:
        return [
            info.finding(
                host,
                title="Operating system reaches end of life within 6 months",
                severity="medium",
                evidence=f"{inv.os_name}: standard support ends {eol} ({days} days)",
            )
        ]
    return []


@host_config_check(
    id="HOST-REBOOT-REQUIRED",
    title="Security updates installed but not active until reboot",
    severity="medium",
    category="config",
    description="Updated packages (often the kernel or core libraries) are installed, but the "
    "running system still uses the old, vulnerable code.",
    remediation="Schedule a reboot, or use live patching (Ubuntu Livepatch, kpatch) for the "
    "kernel.",
)
def reboot_required(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    reasons = []
    kv = inv.keyvals("reboot-required")
    if kv.get("flag"):
        pkgs = kv.get("pkg", [])
        reasons.append("reboot-required flag set" + (f" by {', '.join(pkgs[:5])}" if pkgs else ""))
    if kv.get("needs-restarting") == ["1"]:
        reasons.append("needs-restarting reports a reboot is needed")
    if inv.kernel and inv.installed_kernels:
        newest = max(inv.installed_kernels, key=_kernel_key)
        if rpmvercmp(newest, inv.kernel) > 0 and _same_flavour(newest, inv.kernel):
            reasons.append(f"running kernel {inv.kernel}, newer {newest} installed")
    if not reasons:
        return []
    return [info.finding(host, evidence="; ".join(reasons))]


class _kernel_key:
    def __init__(self, value: str):
        self.value = value

    def __lt__(self, other: "_kernel_key") -> bool:
        return rpmvercmp(self.value, other.value) < 0


def _same_flavour(a: str, b: str) -> bool:
    fa = a.rsplit("-", 1)[-1] if "-" in a else ""
    fb = b.rsplit("-", 1)[-1] if "-" in b else ""
    return fa.isdigit() or fb.isdigit() or fa == fb


def _sshd_config(inv: Inventory) -> dict[str, str] | None:
    text = inv.section("sshd")
    if not text.strip():
        return None
    from_config = text.startswith("#source=config")
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        if from_config and key == "match":
            break  # Match blocks only apply conditionally
        if key not in values:  # sshd uses the first value it sees
            values[key] = parts[1].strip().lower() if len(parts) > 1 else ""
    if from_config:
        values.setdefault("permitrootlogin", "prohibit-password")
        values.setdefault("passwordauthentication", "yes")
        values.setdefault("permitemptypasswords", "no")
    return values


@host_config_check(
    id="HOST-SSH-ROOT-LOGIN",
    title="SSH allows direct root login with a password",
    severity="high",
    category="config",
    description="PermitRootLogin yes lets attackers brute-force the root password directly.",
    remediation="Set 'PermitRootLogin prohibit-password' (or 'no') in sshd_config and reload sshd.",
)
def ssh_root(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    cfg = _sshd_config(inv)
    if cfg and cfg.get("permitrootlogin") == "yes":
        return [info.finding(host, port=None, evidence="PermitRootLogin yes")]
    return []


@host_config_check(
    id="HOST-SSH-PASSWORD-AUTH",
    title="SSH accepts password logins",
    severity="medium",
    category="config",
    description="Password authentication exposes SSH to credential stuffing and brute force. "
    "Key-based authentication is far stronger.",
    remediation="Set 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no' after "
    "confirming key-based access works.",
)
def ssh_password(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    cfg = _sshd_config(inv)
    if cfg and cfg.get("passwordauthentication") == "yes":
        return [info.finding(host, evidence="PasswordAuthentication yes")]
    return []


@host_config_check(
    id="HOST-SSH-EMPTY-PASSWORDS",
    title="SSH permits accounts with empty passwords",
    severity="critical",
    category="config",
    description="Any account without a password can log in over SSH with no credentials.",
    remediation="Set 'PermitEmptyPasswords no' in sshd_config.",
)
def ssh_empty(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    cfg = _sshd_config(inv)
    if cfg and cfg.get("permitemptypasswords") == "yes":
        return [info.finding(host, evidence="PermitEmptyPasswords yes")]
    return []


@host_config_check(
    id="HOST-UID0-ACCOUNT",
    title="Non-root account with UID 0",
    severity="critical",
    category="config",
    description="Accounts with UID 0 have full root privileges. An unexpected one is a common "
    "persistence backdoor.",
    remediation="Investigate the account; remove it or give it a normal UID.",
)
def uid0(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    extra = [u for u in inv.section("uid0").split() if u and u != "root"]
    if not extra:
        return []
    return [info.finding(host, evidence=f"UID 0 accounts: {', '.join(extra)}")]


@host_config_check(
    id="HOST-EMPTY-PASSWORD",
    title="Account with an empty password",
    severity="critical",
    category="config",
    description="These accounts have no password hash, so anyone can log in as them locally "
    "(and remotely, depending on service configuration).",
    remediation="Lock the accounts (passwd -l <user>) or set strong passwords.",
)
def empty_password(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    users = [u for u in inv.section("empty-passwords").split() if u]
    if not users:
        return []
    return [info.finding(host, evidence=f"Empty password field: {', '.join(users[:10])}")]


@host_config_check(
    id="HOST-SENSITIVE-FILE-PERMS",
    title="Password files have unsafe permissions",
    severity="critical",
    category="config",
    description="World-readable /etc/shadow exposes password hashes to every local user; a "
    "world-writable /etc/passwd lets any user become root.",
    remediation="chmod 640 /etc/shadow /etc/gshadow; chmod 644 /etc/passwd; chmod 440 /etc/sudoers",
)
def file_perms(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    problems = []
    for line in inv.section("file-perms").splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[0].isdigit():
            continue
        mode, _, path = int(parts[0], 8), parts[1], parts[2]
        if path in ("/etc/shadow", "/etc/gshadow") and mode & 0o004:
            problems.append(f"{path} is world-readable ({parts[0]})")
        if mode & 0o002:
            problems.append(f"{path} is world-writable ({parts[0]})")
    if not problems:
        return []
    return [info.finding(host, evidence="; ".join(problems))]


@host_config_check(
    id="HOST-SUDO-NOPASSWD",
    title="Passwordless sudo configured",
    severity="low",
    category="config",
    description="Accounts that can run sudo without a password turn any compromise of that "
    "account (or its SSH key) into instant root.",
    remediation="Require a password for sudo, or limit NOPASSWD to specific commands.",
)
def sudo_nopasswd(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    lines = [ln.strip() for ln in inv.section("sudoers").splitlines() if "NOPASSWD" in ln]
    broad = [ln for ln in lines if ln.rstrip().endswith("ALL")]
    if not broad:
        return []
    return [info.finding(host, evidence="; ".join(broad[:5]))]


@host_config_check(
    id="HOST-NO-AUTO-UPDATES",
    title="Automatic security updates are not enabled",
    severity="low",
    category="config",
    description="Without automatic security updates, patches depend on someone remembering "
    "to apply them - the most common reason known vulnerabilities stay open.",
    remediation="Debian/Ubuntu: apt install unattended-upgrades && dpkg-reconfigure "
    "unattended-upgrades. RHEL family: dnf install dnf-automatic && systemctl enable --now "
    "dnf-automatic-install.timer.",
)
def auto_updates(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    fmt = inv.package_format
    if fmt not in ("deb", "rpm"):
        return []
    kv = inv.keyvals("auto-updates")
    units = {}
    for value in kv.get("unit", []):
        name, _, state = value.partition(" ")
        units[name] = state.strip()
    if fmt == "deb":
        apt_lines = " ".join(kv.get("apt", []))
        installed = any(p.name == "unattended-upgrades" for p in inv.packages)
        if installed and 'Unattended-Upgrade "1"' in apt_lines:
            return []
        evidence = "unattended-upgrades not installed" if not installed else (
            'APT::Periodic::Unattended-Upgrade is not "1"'
        )
    else:
        if any(units.get(u) == "enabled" for u in
               ("dnf-automatic.timer", "dnf-automatic-install.timer", "yum-cron.service")):  # fmt: skip
            return []
        evidence = "dnf-automatic / yum-cron not enabled"
    return [info.finding(host, evidence=evidence)]


@host_config_check(
    id="HOST-NO-FIREWALL",
    title="No host firewall rules active",
    severity="low",
    category="config",
    description="The host accepts connections on every listening port from any address. A "
    "host firewall limits the damage when a service is accidentally exposed.",
    remediation="Enable ufw / firewalld / nftables with a default-deny inbound policy.",
)
def no_firewall(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    if inv.uid != 0:
        return []  # rule listing needs root; unknown rather than absent
    kv = inv.keyvals("firewall")
    if not kv:
        return []
    if any("active" in v and "inactive" not in v for v in kv.get("ufw", [])):
        return []
    if "running" in kv.get("firewalld", []):
        return []
    counts = [int(v) for k in ("nft_rules", "iptables_rules") for v in kv.get(k, []) if v.isdigit()]
    if any(c > 0 for c in counts):
        return []
    exposed = [s for s in inv.listening if not s.loopback and s.proto == "tcp"]
    if not exposed:
        return []
    ports = sorted({s.port for s in exposed})
    return [info.finding(host, evidence=f"No rules found; listening on TCP {', '.join(map(str, ports[:12]))}")]


@host_config_check(
    id="HOST-ASLR-DISABLED",
    title="Address space layout randomization (ASLR) is weakened",
    severity="medium",
    category="config",
    description="kernel.randomize_va_space is below 2, making memory corruption exploits far "
    "more reliable.",
    remediation="sysctl -w kernel.randomize_va_space=2 and persist it in /etc/sysctl.d/.",
)
def aslr(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    value = inv.keyvals("sysctl").get("kernel/randomize_va_space", [""])[0]
    if value in ("0", "1"):
        return [info.finding(host, evidence=f"kernel.randomize_va_space = {value}")]
    return []


_DATA_PORTS = {
    6379: "Redis", 11211: "memcached", 27017: "MongoDB", 9200: "Elasticsearch",
    5432: "PostgreSQL", 3306: "MySQL/MariaDB", 5984: "CouchDB", 2375: "Docker API",
}  # fmt: skip


@host_config_check(
    id="HOST-DATASTORE-ALL-INTERFACES",
    title="Data store listening on all network interfaces",
    severity="medium",
    category="config",
    description="Databases and caches should usually listen only on localhost or a private "
    "interface. Listening on 0.0.0.0 relies entirely on the network firewall.",
    remediation="Bind the service to 127.0.0.1 or a private address (e.g. 'bind 127.0.0.1' "
    "for Redis, bind-address for MySQL, listen_addresses for PostgreSQL).",
)
def datastore_binding(info: CheckInfo, inv: Inventory, host: str) -> list[Finding]:
    found = []
    for sock in inv.listening:
        if sock.proto == "tcp" and sock.port in _DATA_PORTS and sock.address in ("0.0.0.0", "::", "*"):
            found.append(f"{_DATA_PORTS[sock.port]} on {sock.address}:{sock.port}")
    if not found:
        return []
    return [info.finding(host, evidence="; ".join(sorted(set(found))))]
