"""Core data structures shared by every part of the scanner."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES))}


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, SEVERITY_RANK["unknown"])


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score onto the standard qualitative scale."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


@dataclass
class Service:
    host: str
    port: int
    proto: str = "tcp"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    banner: str = ""
    tls: bool = False

    @property
    def label(self) -> str:
        bits = [self.name]
        if self.product:
            bits.append(self.product + (f" {self.version}" if self.version else ""))
        return " / ".join(bits)


@dataclass
class Package:
    name: str
    version: str
    source_name: str = ""
    source_version: str = ""
    arch: str = ""
    format: str = ""  # deb, rpm, apk


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    host: str
    category: str = "network"  # network | package | config
    port: int | None = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: str = "confirmed"  # confirmed | likely | potential
    cves: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    package: str | None = None
    binaries: list[str] = field(default_factory=list)
    installed_version: str | None = None
    fixed_version: str | None = None
    advisory: str | None = None
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    exploit_maturity: str = ""   # active | weaponized | poc | unproven
    exploit_refs: list[str] = field(default_factory=list)
    exposed: bool = False
    risk: float = 0.0
    priority: str = ""
    status: str = ""  # new | existing (filled in when diffing against a previous scan)

    @property
    def key(self) -> str:
        """Stable identity used to compare findings across scans."""
        raw = "|".join(
            [
                self.host,
                self.check_id,
                str(self.port or ""),
                self.package or "",
                self.advisory or "",
                ",".join(sorted(self.cves)),
            ]
        )
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["key"] = self.key
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    alive: bool = False
    credentialed: bool = False
    os_name: str = ""
    os_id: str = ""
    os_version: str = ""
    kernel: str = ""
    package_count: int = 0
    package_format: str = ""
    services: list[Service] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HostResult":
        data = dict(data)
        data["services"] = [Service(**s) for s in data.get("services", [])]
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class ScanResult:
    scan_id: str
    name: str
    targets: list[str]
    started: str
    finished: str = ""
    hosts: list[HostResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    previous_scan_id: str | None = None
    options: dict[str, Any] = field(default_factory=dict)
    vulndb: dict[str, Any] = field(default_factory=dict)
    capture: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        counts = {s: 0 for s in SEVERITIES}
        priorities: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            priorities[f.priority] = priorities.get(f.priority, 0) + 1
        return {
            "hosts_scanned": len(self.hosts),
            "hosts_alive": sum(1 for h in self.hosts if h.alive),
            "hosts_credentialed": sum(1 for h in self.hosts if h.credentialed),
            "findings": len(self.findings),
            "by_severity": counts,
            "by_priority": priorities,
            "kev": sum(1 for f in self.findings if f.kev),
            "new": sum(1 for f in self.findings if f.status == "new"),
            "fixed": len(self.fixed),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "name": self.name,
            "targets": self.targets,
            "started": self.started,
            "finished": self.finished,
            "previous_scan_id": self.previous_scan_id,
            "options": self.options,
            "vulndb": self.vulndb,
            "capture": self.capture,
            "summary": self.summary(),
            "hosts": [h.to_dict() for h in self.hosts],
            "findings": [f.to_dict() for f in self.findings],
            "fixed": [f.to_dict() for f in self.fixed],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            scan_id=data["scan_id"],
            name=data.get("name", ""),
            targets=data.get("targets", []),
            started=data.get("started", ""),
            finished=data.get("finished", ""),
            previous_scan_id=data.get("previous_scan_id"),
            options=data.get("options", {}),
            vulndb=data.get("vulndb", {}),
            capture=data.get("capture", {}),
            hosts=[HostResult.from_dict(h) for h in data.get("hosts", [])],
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            fixed=[Finding.from_dict(f) for f in data.get("fixed", [])],
        )
