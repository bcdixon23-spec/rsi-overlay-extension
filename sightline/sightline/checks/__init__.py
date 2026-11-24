"""Check registry.

Network checks run against each discovered service. Host checks run against
the inventory collected from a credentialed host. Each check declares its
metadata once, so reports and `sightline checks` stay in sync with the code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from sightline.models import Finding, Service


@dataclass
class CheckContext:
    timeout: float = 3.0
    hostname: str | None = None  # set when the user gave a DNS name, for TLS name checks
    public: bool = False  # target address is internet-routable
    cache: dict = field(default_factory=dict)


@dataclass
class CheckInfo:
    id: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)

    def finding(self, host: str, **overrides) -> Finding:
        data = dict(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            host=host,
            category=self.category,
            description=self.description,
            remediation=self.remediation,
            references=list(self.references),
        )
        data.update(overrides)
        return Finding(**data)


ServiceCheck = Callable[[CheckInfo, Service, CheckContext], Awaitable[list[Finding]]]
HostNetCheck = Callable[[CheckInfo, str, list[Service], CheckContext], Awaitable[list[Finding]]]


@dataclass
class Registered:
    info: CheckInfo
    func: Callable
    applies: Callable[[Service], bool] | None = None
    kind: str = "service"  # service | host-network | host-config


REGISTRY: list[Registered] = []


def _register(kind, applies, **meta):
    def deco(func):
        info = CheckInfo(**meta)
        REGISTRY.append(Registered(info, func, applies, kind))
        return func

    return deco


def service_check(applies: Callable[[Service], bool], **meta):
    return _register("service", applies, **meta)


def host_network_check(**meta):
    return _register("host-network", None, **meta)


def host_config_check(**meta):
    return _register("host-config", None, **meta)


def load_all() -> list[Registered]:
    # Importing the modules registers their checks.
    from sightline.checks import host, http, network, tls  # noqa: F401

    return REGISTRY


def by_kind(kind: str) -> list[Registered]:
    return [r for r in load_all() if r.kind == kind]
