"""Match a host's installed packages against distro advisories."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cmp_to_key

from sightline.collect.inventory import Inventory
from sightline.models import Finding, Package
from sightline.vulndb.store import CVE_RE, VulnDB
from sightline.vulndb.versions import comparator

DISTRO_LABEL = {
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "alpine": "Alpine",
    "rocky": "Rocky Linux",
    "almalinux": "AlmaLinux",
    "redhat": "Red Hat",
}


def _event_version(event: dict) -> str:
    for key in ("introduced", "fixed", "last_affected", "limit"):
        if key in event:
            return str(event[key])
    return ""


def evaluate_range(cmp, version: str, events: list[dict]) -> tuple[bool, str | None]:
    """OSV range evaluation. Returns (affected, fixed_version_if_any)."""

    def order(e1: dict, e2: dict) -> int:
        a, b = _event_version(e1), _event_version(e2)
        if a == b:
            return 0
        if a == "0":
            return -1
        if b == "0":
            return 1
        return cmp(a, b)

    events = sorted((e for e in events if _event_version(e)), key=cmp_to_key(order))
    affected = False
    for event in events:
        if "introduced" in event:
            intro = str(event["introduced"])
            if intro == "0" or cmp(version, intro) >= 0:
                affected = True
        elif "fixed" in event:
            if cmp(version, str(event["fixed"])) >= 0:
                affected = False
        elif "last_affected" in event:
            if cmp(version, str(event["last_affected"])) > 0:
                affected = False
        elif "limit" in event:
            if cmp(version, str(event["limit"])) >= 0:
                affected = False
    if not affected:
        return False, None
    fixed = None
    for event in events:
        if "fixed" in event and cmp(str(event["fixed"]), version) > 0:
            fixed = str(event["fixed"])
            break
    return True, fixed


def is_affected(family: str, version: str, ranges, versions) -> tuple[bool, str | None]:
    cmp = comparator(family)
    if family in ("rocky", "almalinux", "redhat"):
        # Advisories sometimes omit the epoch; borrow the installed one so that
        # "1:3.0.7-24" is compared like-for-like against "3.0.7-25".
        epoch = version.split(":", 1)[0] if ":" in version else "0"
        base_cmp = cmp

        def cmp(a: str, b: str, _base=base_cmp) -> int:  # noqa: F811
            if ":" not in a:
                a = f"{epoch}:{a}"
            if ":" not in b:
                b = f"{epoch}:{b}"
            return _base(a, b)

        if versions and any(v.split(":")[-1] == version.split(":")[-1] for v in versions):
            return True, None
    elif versions and version in versions:
        return True, None
    best_fixed = None
    hit = False
    for events in ranges or []:
        affected, fixed = evaluate_range(cmp, version, events)
        if affected:
            hit = True
            if fixed and (best_fixed is None or cmp(fixed, best_fixed) < 0):
                best_fixed = fixed
    return hit, best_fixed


@dataclass
class _Hit:
    adv_id: str
    group: str  # source package name
    installed: str
    fixed: str | None
    variant: str
    row: dict
    cves: list[str]
    binaries: set[str] = field(default_factory=set)


def _upgrade_command(fmt: str, binaries: list[str]) -> str:
    names = " ".join(sorted(binaries)[:12])
    if fmt == "deb":
        return f"sudo apt-get update && sudo apt-get install --only-upgrade {names}"
    if fmt == "rpm":
        return f"sudo dnf upgrade {names}"
    if fmt == "apk":
        return f"apk update && apk upgrade {names}"
    return f"upgrade {names}"


def match_inventory(db: VulnDB, inv: Inventory, host: str) -> tuple[list[Finding], list[str]]:
    """Return (findings, notes) for one host."""
    notes: list[str] = []
    key = inv.osv_key()
    if not key:
        notes.append(
            f"Package vulnerability matching is not available for {inv.os_name or 'this OS'} yet; "
            "network and configuration checks still ran."
        )
        return [], notes
    family, release = key
    if not db.has_release(family, release):
        notes.append(
            f"No advisory data for {DISTRO_LABEL.get(family, family)} {release} in the local "
            f"database. Run: sightline db update {family}"
        )
        return [], notes

    # name -> list of (package, version to compare)
    by_name: dict[str, list[tuple[Package, str]]] = {}
    for pkg in inv.packages:
        by_name.setdefault(pkg.name, []).append((pkg, pkg.version))
        if pkg.source_name and pkg.source_name != pkg.name:
            by_name.setdefault(pkg.source_name, []).append((pkg, pkg.source_version or pkg.version))

    rows = db.candidates(family, release, by_name.keys())
    hits: dict[tuple[str, str], _Hit] = {}
    for row in rows:
        ranges = json.loads(row["ranges"]) if row["ranges"] else []
        versions = json.loads(row["versions"]) if row["versions"] else []
        seen_versions: dict[str, tuple[bool, str | None]] = {}
        for pkg, version in by_name.get(row["package"], []):
            if version not in seen_versions:
                seen_versions[version] = is_affected(family, version, ranges, versions)
            affected, fixed = seen_versions[version]
            if not affected:
                continue
            group = pkg.source_name or pkg.name
            hk = (group, row["adv_id"])
            if hk not in hits:
                hits[hk] = _Hit(
                    adv_id=row["adv_id"],
                    group=group,
                    installed=version,
                    fixed=fixed,
                    variant=row["variant"],
                    row=dict(row),
                    cves=json.loads(row["cves"] or "[]"),
                )
            hits[hk].binaries.add(pkg.name)

    findings = _consolidate(hits, family, inv, host)
    return findings, notes


def _consolidate(hits: dict, family: str, inv: Inventory, host: str) -> list[Finding]:
    """Collapse overlapping advisories (e.g. USN + UBUNTU-CVE) into one finding per CVE."""
    by_group: dict[str, list[_Hit]] = {}
    for hit in hits.values():
        by_group.setdefault(hit.group, []).append(hit)

    findings: list[Finding] = []
    distro = DISTRO_LABEL.get(family, family)
    fmt = inv.package_format
    for group, group_hits in by_group.items():
        # Standard (non-Pro) streams first, CVE-centric records before bulletins.
        group_hits.sort(key=lambda h: (h.variant != "", not CVE_RE.search(h.adv_id), h.adv_id))
        covered: set[str] = set()
        for hit in group_hits:
            cves = hit.cves
            if CVE_RE.search(hit.adv_id):
                cves = [c for c in cves if c not in covered]
                if not cves:
                    continue
            else:
                remaining = [c for c in cves if c not in covered]
                if cves and not remaining:
                    continue
                cves = remaining or cves
            covered.update(cves)
            findings.append(_make_finding(hit, cves, distro, fmt, host))
    return findings


def _make_finding(hit: _Hit, cves: list[str], distro: str, fmt: str, host: str) -> Finding:
    row = hit.row
    label = cves[0] if len(cves) == 1 else hit.adv_id
    summary = (row.get("summary") or "").strip()
    if not summary:
        details = (row.get("details") or "").strip()
        summary = details.split("\n", 1)[0][:160]
    title = f"{hit.group}: {label}" + (f" - {summary}" if summary else "")
    binaries = sorted(hit.binaries)
    if hit.fixed:
        remediation = f"Upgrade to {hit.fixed} or later: {_upgrade_command(fmt, binaries)}"
        if hit.variant == "pro":
            remediation += " (the fix ships through Ubuntu Pro / ESM)"
    else:
        remediation = (
            f"{distro} has not released a fixed package yet. Track the advisory, and reduce "
            "exposure (disable, firewall or remove the package) if it is reachable."
        )
    refs = json.loads(row.get("refs") or "[]")
    evidence = f"Installed {', '.join(binaries)} {hit.installed}"
    if hit.fixed:
        evidence += f"; fixed in {hit.fixed}"
    return Finding(
        check_id="PKG-VULN",
        title=title[:200],
        severity=row.get("severity") or "unknown",
        host=host,
        category="package",
        description=(row.get("details") or summary or "")[:2000],
        evidence=evidence,
        remediation=remediation,
        confidence="confirmed",
        cves=cves,
        references=refs,
        package=hit.group,
        binaries=binaries,
        installed_version=hit.installed,
        fixed_version=hit.fixed,
        advisory=hit.adv_id,
        cvss=row.get("cvss"),
    )


def enrich(db: VulnDB, findings: list[Finding]) -> None:
    """Attach CISA KEV and EPSS data to findings in place."""
    cves = {c for f in findings for c in f.cves}
    if not cves:
        return
    kev = db.kev_entries(cves)
    epss = db.epss_scores(cves)
    for f in findings:
        if any(c in kev for c in f.cves):
            f.kev = True
            entry = next(kev[c] for c in f.cves if c in kev)
            note = f"Listed in CISA Known Exploited Vulnerabilities (added {entry['date_added']})"
            if (entry["ransomware"] or "").lower() == "known":
                note += "; used in ransomware campaigns"
            f.evidence = (f.evidence + ". " if f.evidence else "") + note
        scores = [epss[c] for c in f.cves if c in epss]
        if scores:
            f.epss = max(scores)
