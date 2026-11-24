"""Helpers shared by all report formats."""

from __future__ import annotations

from dataclasses import dataclass, field

from sightline.models import Finding, ScanResult
from sightline.risk import PRIORITIES

UPGRADE_TEMPLATES = {
    "deb": "sudo apt-get update && sudo apt-get install --only-upgrade {pkgs}",
    "rpm": "sudo dnf upgrade {pkgs}",
    "apk": "apk update && apk upgrade {pkgs}",
}


@dataclass
class PatchItem:
    package: str
    binaries: set[str] = field(default_factory=set)
    fixed_version: str = ""
    findings: int = 0
    kev: int = 0
    top_priority: str = "monitor"
    max_risk: float = 0.0


@dataclass
class HostPatchPlan:
    host: str
    label: str
    package_format: str
    items: list[PatchItem]

    @property
    def command(self) -> str:
        pkgs = sorted({b for item in self.items for b in item.binaries})
        template = UPGRADE_TEMPLATES.get(self.package_format, "upgrade {pkgs}")
        return template.format(pkgs=" ".join(pkgs))

    @property
    def findings_resolved(self) -> int:
        return sum(i.findings for i in self.items)


def patch_plan(result: ScanResult) -> list[HostPatchPlan]:
    """Collapse fixable package findings into one upgrade command per host."""
    by_host: dict[str, dict[str, PatchItem]] = {}
    for f in result.findings:
        if f.category != "package" or not f.fixed_version or not f.package:
            continue
        items = by_host.setdefault(f.host, {})
        item = items.setdefault(f.package, PatchItem(package=f.package))
        item.binaries.update(f.binaries or [f.package])
        item.findings += 1
        item.kev += int(f.kev)
        if f.risk > item.max_risk:
            item.max_risk = f.risk
            item.fixed_version = f.fixed_version
        if PRIORITIES.index(f.priority or "monitor") < PRIORITIES.index(item.top_priority):
            item.top_priority = f.priority
    hosts = {h.address: h for h in result.hosts}
    plans = []
    for address, items in by_host.items():
        h = hosts.get(address)
        label = f"{address} ({h.hostname})" if h and h.hostname else address
        ordered = sorted(items.values(), key=lambda i: (-i.max_risk, i.package))
        plans.append(HostPatchPlan(address, label, h.package_format if h else "", ordered))
    plans.sort(key=lambda p: -max((i.max_risk for i in p.items), default=0))
    return plans


def location(f: Finding) -> str:
    if f.package:
        return f.package
    if f.port:
        return f"port {f.port}"
    return "host"


def counts_by_priority(findings: list[Finding]) -> dict[str, int]:
    out = {p: 0 for p in PRIORITIES}
    for f in findings:
        out[f.priority or "monitor"] = out.get(f.priority or "monitor", 0) + 1
    return out
