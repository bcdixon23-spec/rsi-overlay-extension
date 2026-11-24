"""Turn user-supplied target specs into a list of hosts to scan.

Accepted forms (comma or whitespace separated, or one per line in an @file):
  192.168.1.10          single address
  192.168.1.0/24        CIDR block (network and broadcast addresses skipped)
  10.0.0.5-10.0.0.40    full address range
  10.0.0.5-40           short range (last octet)
  web01.example.com     hostname
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

MAX_HOSTS_DEFAULT = 4096


class TargetError(ValueError):
    pass


def _split(spec: str) -> list[str]:
    out: list[str] = []
    for chunk in spec.replace(",", " ").split():
        chunk = chunk.strip()
        if not chunk or chunk.startswith("#"):
            continue
        if chunk.startswith("@"):
            path = Path(chunk[1:]).expanduser()
            if not path.is_file():
                raise TargetError(f"target file not found: {path}")
            for line in path.read_text().splitlines():
                line = line.split("#", 1)[0]
                out.extend(_split(line))
        else:
            out.append(chunk)
    return out


def _expand_one(item: str) -> list[str]:
    if "/" in item:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise TargetError(f"invalid network {item!r}: {exc}") from None
        if net.num_addresses == 1:
            return [str(net.network_address)]
        hosts = list(net.hosts())
        return [str(h) for h in hosts]
    if "-" in item and not _looks_like_hostname(item):
        start_s, end_s = item.split("-", 1)
        try:
            start = ipaddress.ip_address(start_s)
        except ValueError:
            raise TargetError(f"invalid range start {start_s!r}") from None
        if end_s.isdigit() and "." not in end_s and ":" not in end_s:
            if start.version != 4:
                raise TargetError("short ranges (a.b.c.d-N) only work for IPv4")
            prefix = str(start).rsplit(".", 1)[0]
            end = ipaddress.ip_address(f"{prefix}.{end_s}")
        else:
            try:
                end = ipaddress.ip_address(end_s)
            except ValueError:
                raise TargetError(f"invalid range end {end_s!r}") from None
        if start.version != end.version or int(end) < int(start):
            raise TargetError(f"invalid range {item!r}")
        return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
    return [item]


def _looks_like_hostname(item: str) -> bool:
    try:
        ipaddress.ip_address(item.split("-", 1)[0])
        return False
    except ValueError:
        return True


def expand_targets(specs: list[str] | str, max_hosts: int = MAX_HOSTS_DEFAULT) -> list[str]:
    if isinstance(specs, str):
        specs = [specs]
    items: list[str] = []
    for spec in specs:
        items.extend(_split(spec))
    hosts: list[str] = []
    seen: set[str] = set()
    for item in items:
        for host in _expand_one(item):
            if host not in seen:
                seen.add(host)
                hosts.append(host)
            if len(hosts) > max_hosts:
                raise TargetError(
                    f"target list expands to more than {max_hosts} hosts; "
                    "narrow it or raise --max-hosts"
                )
    if not hosts:
        raise TargetError("no targets given")
    return hosts


def resolve(host: str) -> str | None:
    """Return an IP address for host, or None if it cannot be resolved."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    for family in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family:
                return info[4][0]
    return None


def is_public(address: str) -> bool:
    """True if the address is routable on the public internet."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_global
