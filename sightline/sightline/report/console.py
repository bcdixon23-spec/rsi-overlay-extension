"""Terminal output."""

from __future__ import annotations

import os
import sys
import textwrap

from sightline.models import ScanResult
from sightline.report.common import counts_by_priority, location, patch_plan
from sightline.risk import PRIORITY_LABEL

_COLORS = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
    "unknown": "\033[2m",
    "fix-now": "\033[1;31m",
    "fix-soon": "\033[1;33m",
    "plan": "\033[36m",
    "monitor": "\033[2m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[32m",
}
_RESET = "\033[0m"


def _use_color(stream) -> bool:
    return stream.isatty() and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"


def render(result: ScanResult, stream=None, limit: int = 15, verbose: bool = False) -> None:
    stream = stream or sys.stdout
    color = _use_color(stream)

    def c(key: str, text: str) -> str:
        return f"{_COLORS.get(key, '')}{text}{_RESET}" if color else text

    def out(line: str = "") -> None:
        print(line, file=stream)

    s = result.summary()
    width = 100
    out()
    out(c("bold", f"Sightline scan {result.scan_id}") + c("dim", f"  {result.started}"))
    out(
        f"Hosts: {s['hosts_alive']} up of {s['hosts_scanned']} scanned, "
        f"{s['hosts_credentialed']} with credentialed inventory"
    )
    counts = counts_by_priority(result.findings)
    parts = [c(p, f"{PRIORITY_LABEL[p]}: {n}") for p, n in counts.items()]
    out("Findings: " + "   ".join(parts))
    extra = [f"known exploited: {s['kev']}"]
    if result.previous_scan_id:
        extra += [f"new since last scan: {s['new']}", c("green", f"fixed since last scan: {s['fixed']}")]
    out(c("dim", "          ") + "   ".join(extra))

    for prio in ("fix-now", "fix-soon"):
        items = [f for f in result.findings if f.priority == prio]
        if not items:
            continue
        out()
        out(c(prio, f"{PRIORITY_LABEL[prio].upper()} ({len(items)})"))
        for f in items[:limit]:
            sev = c(f.severity, f" {f.severity.upper():8} ")
            flags = []
            if f.kev:
                flags.append(c("fix-now", "KEV"))
            if f.status == "new" and result.previous_scan_id:
                flags.append(c("bold", "NEW"))
            if f.confidence != "confirmed":
                flags.append(c("dim", f.confidence))
            where = f"{f.host}" + (f":{f.port}" if f.port else "")
            out(f"  {sev} {c('bold', f'{f.risk:5.1f}')}  {where:<21} {f.title[:width - 40]}  {' '.join(flags)}")
            if verbose or prio == "fix-now":
                if f.evidence:
                    out(c("dim", "             " + textwrap.shorten(f"evidence: {f.evidence}", width)))
                out(c("dim", "             " + textwrap.shorten(f"fix: {f.remediation}", width)))
        if len(items) > limit:
            out(c("dim", f"  ... and {len(items) - limit} more (see the HTML or JSON report)"))

    plans = patch_plan(result)
    if plans:
        out()
        out(c("bold", "PATCH PLAN") + c("dim", "  (one command per host resolves all fixable package findings)"))
        for plan in plans[:limit]:
            out(f"  {plan.label}: {plan.findings_resolved} findings in {len(plan.items)} packages")
            out(c("dim", "    " + textwrap.shorten(plan.command, width + 20, placeholder=" ...")))

    out()
    out(c("bold", "HOSTS"))
    for h in result.hosts:
        if not h.alive and not h.errors:
            continue
        host_findings = [f for f in result.findings if f.host == h.address]
        name = f" ({h.hostname})" if h.hostname else ""
        os_name = f"  {h.os_name}" if h.os_name else ""
        cred = c("green", " [credentialed]") if h.credentialed else ""
        out(f"  {h.address}{name}{os_name}{cred}  - {len(host_findings)} findings")
        if h.services:
            svc = ", ".join(f"{x.port}/{x.name}" + (f" ({x.product} {x.version})".rstrip() if x.product else "")
                            for x in h.services)  # fmt: skip
            out(c("dim", textwrap.fill(svc, width, initial_indent="    ", subsequent_indent="    ")))
        for err in h.errors:
            out(c("high", f"    error: {err}"))
        for note in h.notes:
            if verbose or not note.startswith("check "):
                out(c("dim", "    " + textwrap.shorten(f"note: {note}", width + 6)))
    if result.fixed:
        out()
        out(c("green", f"FIXED SINCE LAST SCAN ({len(result.fixed)})"))
        for f in result.fixed[:limit]:
            out(c("green", f"  {f.host:<15} {location(f):<20} {f.title[:70]}"))
    out()
