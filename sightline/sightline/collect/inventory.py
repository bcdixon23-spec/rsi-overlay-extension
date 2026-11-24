"""Gather OS, package and configuration data from a host with one shell script."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from sightline.models import Package

COLLECTOR_SCRIPT = r"""
export LC_ALL=C
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
have() { command -v "$1" >/dev/null 2>&1; }
s() { printf '\n@@SL:%s@@\n' "$1"; }

s os-release
cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null
s uname
uname -srm 2>/dev/null
s hostname
hostname 2>/dev/null || cat /etc/hostname 2>/dev/null
s uid
id -u 2>/dev/null
s dpkg
have dpkg-query && dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n' 2>/dev/null
s rpm
have rpm && rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n' 2>/dev/null
s apk
[ -f /lib/apk/db/installed ] && grep -E '^(P|V|o|A):|^$' /lib/apk/db/installed
s kernels
ls -1 /lib/modules 2>/dev/null
s reboot-required
[ -f /var/run/reboot-required ] && echo "flag=yes"
[ -f /var/run/reboot-required.pkgs ] && sed 's/^/pkg=/' /var/run/reboot-required.pkgs
have needs-restarting && { needs-restarting -r >/dev/null 2>&1; echo "needs-restarting=$?"; }
s sshd
if have sshd; then
  if sshd -T 2>/dev/null; then :; else
    echo "#source=config"
    cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null
  fi
fi
s listening
ss -H -tulpn 2>/dev/null || ss -H -tuln 2>/dev/null || netstat -tulpn 2>/dev/null
s proc-net
for f in /proc/net/tcp /proc/net/tcp6; do [ -r "$f" ] && sed "s|^|${f##*/} |" "$f"; done
s uid0
awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null
s file-perms
for f in /etc/passwd /etc/shadow /etc/gshadow /etc/sudoers; do
  [ -e "$f" ] && stat -c '%a %U %n' "$f" 2>/dev/null
done
s empty-passwords
[ -r /etc/shadow ] && awk -F: '$2 == "" {print $1}' /etc/shadow
s sudoers
cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^[[:space:]]*#' | grep 'NOPASSWD'
s auto-updates
[ -f /etc/apt/apt.conf.d/20auto-upgrades ] && sed 's/^/apt=/' /etc/apt/apt.conf.d/20auto-upgrades
have systemctl && for u in unattended-upgrades.service apt-daily-upgrade.timer dnf-automatic.timer dnf-automatic-install.timer yum-cron.service; do
  printf 'unit=%s %s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null)"
done
s firewall
have ufw && printf 'ufw=%s\n' "$(ufw status 2>/dev/null | head -n1)"
have firewall-cmd && printf 'firewalld=%s\n' "$(firewall-cmd --state 2>/dev/null)"
have nft && printf 'nft_rules=%s\n' "$(nft list ruleset 2>/dev/null | grep -cE '(accept|drop|reject)')"
have iptables && printf 'iptables_rules=%s\n' "$(iptables -S 2>/dev/null | grep -c '^-A')"
s sysctl
for k in kernel/randomize_va_space net/ipv4/ip_forward net/ipv4/tcp_syncookies kernel/kptr_restrict fs/protected_symlinks fs/protected_hardlinks; do
  [ -r "/proc/sys/$k" ] && printf '%s=%s\n' "$k" "$(cat /proc/sys/$k)"
done
s uptime
cat /proc/uptime 2>/dev/null
s end
"""

_SECTION_RE = re.compile(r"^@@SL:([a-z0-9-]+)@@$", re.M)

UBUNTU_CODENAMES = {
    "xenial": "16.04",
    "bionic": "18.04",
    "focal": "20.04",
    "jammy": "22.04",
    "noble": "24.04",
    "oracular": "24.10",
    "plucky": "25.04",
    "questing": "25.10",
    "resolute": "26.04",
}
DEBIAN_CODENAMES = {
    "stretch": "9",
    "buster": "10",
    "bullseye": "11",
    "bookworm": "12",
    "trixie": "13",
    "forky": "14",
}


@dataclass
class ListeningSocket:
    proto: str
    address: str
    port: int
    process: str = ""

    @property
    def loopback(self) -> bool:
        return self.address.startswith("127.") or self.address in ("::1", "[::1]", "localhost")


@dataclass
class Inventory:
    os_release: dict[str, str] = field(default_factory=dict)
    kernel: str = ""
    arch: str = ""
    hostname: str = ""
    uid: int | None = None
    packages: list[Package] = field(default_factory=list)
    listening: list[ListeningSocket] = field(default_factory=list)
    sections: dict[str, str] = field(default_factory=dict)
    installed_kernels: list[str] = field(default_factory=list)

    @property
    def os_id(self) -> str:
        return self.os_release.get("ID", "").lower()

    @property
    def os_version(self) -> str:
        return self.os_release.get("VERSION_ID", "")

    @property
    def os_name(self) -> str:
        return self.os_release.get("PRETTY_NAME") or f"{self.os_id} {self.os_version}".strip()

    @property
    def package_format(self) -> str:
        return self.packages[0].format if self.packages else ""

    def osv_key(self) -> tuple[str, str] | None:
        """Which advisory stream (family, release) applies to this host."""
        osid = self.os_id
        like = self.os_release.get("ID_LIKE", "").lower().split()
        version = self.os_version
        major = version.split(".")[0] if version else ""
        if osid == "ubuntu" and version:
            return "ubuntu", version
        if osid in ("debian", "raspbian") and major.isdigit():
            return "debian", major
        if osid == "alpine" and version:
            return "alpine", ".".join(version.split(".")[:2])
        if osid == "rocky" and major:
            return "rocky", major
        if osid == "almalinux" and major:
            return "almalinux", major
        if osid == "rhel" and major:
            return "redhat", major
        if "ubuntu" in like:
            code = self.os_release.get("UBUNTU_CODENAME", "")
            if code in UBUNTU_CODENAMES:
                return "ubuntu", UBUNTU_CODENAMES[code]
        if "debian" in like:
            code = self.os_release.get("DEBIAN_CODENAME") or self.os_release.get(
                "VERSION_CODENAME", ""
            )
            if code in DEBIAN_CODENAMES:
                return "debian", DEBIAN_CODENAMES[code]
        return None

    def section(self, name: str) -> str:
        return self.sections.get(name, "")

    def keyvals(self, name: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for line in self.section(name).splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out.setdefault(k.strip(), []).append(v.strip())
        return out


def split_sections(output: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(output))
    for idx, m in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(output)
        sections[m.group(1)] = output[m.end() : end].strip("\n")
    return sections


def _parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k] = v.strip().strip('"').strip("'")
    return data


def parse_dpkg(text: str) -> list[Package]:
    pkgs = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        status, name, version, src, src_version, arch = parts[:6]
        if len(status) < 2 or status[1] != "i":
            continue
        name = name.split(":", 1)[0]
        src = (src or name).split(" ", 1)[0]
        pkgs.append(Package(name, version, src, src_version or version, arch, "deb"))
    return pkgs


def _srpm_name(srpm: str) -> str:
    if not srpm or srpm == "(none)":
        return ""
    base = srpm[: -len(".src.rpm")] if srpm.endswith(".src.rpm") else srpm
    parts = base.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else base


def parse_rpm(text: str) -> list[Package]:
    pkgs = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        name, epoch, version, release, srpm, arch = parts[:6]
        if name == "gpg-pubkey":
            continue
        epoch = "0" if epoch in ("(none)", "") else epoch
        evr = f"{epoch}:{version}-{release}"
        pkgs.append(Package(name, evr, _srpm_name(srpm) or name, evr, arch, "rpm"))
    return pkgs


def parse_apk(text: str) -> list[Package]:
    pkgs = []
    current: dict[str, str] = {}

    def flush():
        if current.get("P") and current.get("V"):
            pkgs.append(
                Package(
                    current["P"],
                    current["V"],
                    current.get("o") or current["P"],
                    current["V"],
                    current.get("A", ""),
                    "apk",
                )
            )

    for line in text.splitlines():
        if not line.strip():
            flush()
            current = {}
            continue
        if len(line) > 2 and line[1] == ":":
            current[line[0]] = line[2:].strip()
    flush()
    return pkgs


_SS_PROC_RE = re.compile(r'users:\(\("([^"]+)"')


def parse_listening(text: str) -> list[ListeningSocket]:
    sockets = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        proto = cols[0].lower()
        if proto not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        # ss: Netid State Recv-Q Send-Q Local Peer [Process]
        # netstat: Proto Recv-Q Send-Q Local Foreign [State] PID/Program
        if cols[1].isdigit():  # netstat layout
            local = cols[3]
            if proto.startswith("tcp") and (len(cols) < 6 or cols[5] != "LISTEN"):
                continue
            prog = cols[-1].split("/", 1)[-1] if "/" in cols[-1] else ""
        else:
            if proto.startswith("tcp") and cols[1] != "LISTEN":
                continue
            local = cols[4]
            m = _SS_PROC_RE.search(line)
            prog = m.group(1) if m else ""
        if ":" not in local:
            continue
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%", 1)[0]
        if not port.isdigit():
            continue
        sockets.append(ListeningSocket(proto.rstrip("6"), addr, int(port), prog))
    return sockets


def _hex_ip(value: str) -> str:
    raw = bytes.fromhex(value)
    if len(raw) == 4:
        return ".".join(str(b) for b in reversed(raw))
    # IPv6 is stored as four little-endian 32-bit words
    words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
    return str(ipaddress.IPv6Address(b"".join(words)))


def parse_proc_net(text: str) -> list[ListeningSocket]:
    """Fallback for hosts without ss/netstat: read /proc/net/tcp{,6} (no process names)."""
    sockets = []
    seen = set()
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[1] == "sl" or cols[4] != "0A":  # 0A = LISTEN
            continue
        try:
            hex_addr, hex_port = cols[2].split(":")
            addr, port = _hex_ip(hex_addr), int(hex_port, 16)
        except ValueError:
            continue
        if (addr, port) not in seen:
            seen.add((addr, port))
            sockets.append(ListeningSocket("tcp", addr, port))
    return sockets


def parse_collection(output: str) -> Inventory:
    sections = split_sections(output)
    inv = Inventory(sections=sections)
    inv.os_release = _parse_os_release(sections.get("os-release", ""))
    uname = sections.get("uname", "").split()
    if len(uname) >= 2:
        inv.kernel = uname[1]
    if len(uname) >= 3:
        inv.arch = uname[2]
    inv.hostname = sections.get("hostname", "").strip().splitlines()[0] if sections.get(
        "hostname", ""
    ).strip() else ""
    uid = sections.get("uid", "").strip()
    inv.uid = int(uid) if uid.isdigit() else None
    inv.packages = (
        parse_dpkg(sections.get("dpkg", ""))
        or parse_rpm(sections.get("rpm", ""))
        or parse_apk(sections.get("apk", ""))
    )
    inv.listening = parse_listening(sections.get("listening", "")) or parse_proc_net(
        sections.get("proc-net", "")
    )
    inv.installed_kernels = [k for k in sections.get("kernels", "").split() if k]
    return inv
