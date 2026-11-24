"""The scan engine: discovery -> fingerprinting -> checks -> collection -> matching -> ranking."""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from sightline import checks
from sightline.checks import CheckContext
from sightline.collect.inventory import COLLECTOR_SCRIPT, Inventory, parse_collection
from sightline.collect.runner import CollectionError, LocalRunner, SSHRunner
from sightline.config import scans_path, vulndb_path
from sightline.exploitintel import enrich as exploit_enrich
from sightline.models import Finding, HostResult, ScanResult
from sightline.netscan import DEFAULT_PORTS, fingerprint, scan_ports
from sightline.risk import mark_exposure, prioritize
from sightline.storage import ScanStore, apply_diff
from sightline.targets import expand_targets, is_public, resolve
from sightline.vulndb import feeds
from sightline.vulndb.matcher import enrich, match_inventory
from sightline.vulndb.store import VulnDB

Progress = Callable[[str], None]
LOCAL_NAMES = {"localhost", "127.0.0.1", "::1"}


@dataclass
class ScanOptions:
    targets: list[str] = field(default_factory=list)
    name: str = ""
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    network: bool = True
    udp: bool = True
    local: bool = False
    ssh: bool = False
    ssh_user: str | None = None
    ssh_key: str | None = None
    ssh_port: int = 22
    ssh_options: list[str] = field(default_factory=list)
    sudo: bool = False
    strict_host_keys: bool = False
    connect_timeout: float = 1.0
    timeout: float = 3.0
    concurrency: int = 400
    host_concurrency: int = 32
    max_hosts: int = 4096
    auto_update_db: bool = True

    def public_dict(self) -> dict:
        return {
            "ports": len(self.ports),
            "network": self.network,
            "credentialed": self.ssh or self.local,
            "local": self.local,
            "ssh_user": self.ssh_user,
            "sudo": self.sudo,
        }


@dataclass
class _HostOutcome:
    host: HostResult
    findings: list[Finding]
    inventory: Inventory | None = None


def new_scan_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _run_service_checks(services, ctx: CheckContext, host: HostResult) -> list[Finding]:
    tasks = []
    for reg in checks.by_kind("service"):
        for svc in services:
            try:
                applies = reg.applies(svc)
            except Exception:  # noqa: BLE001 - a broken predicate must not stop the scan
                applies = False
            if applies:
                tasks.append(_safe(reg.func(reg.info, svc, ctx), reg.info.id, host))
    results = await asyncio.gather(*tasks)
    return [f for batch in results for f in batch]


async def _safe(coro, check_id: str, host: HostResult) -> list[Finding]:
    try:
        return await coro or []
    except Exception as exc:  # noqa: BLE001
        host.notes.append(f"check {check_id} failed: {type(exc).__name__}: {exc}")
        return []


async def _scan_host(target: str, opts: ScanOptions, sem: asyncio.Semaphore, progress: Progress) -> _HostOutcome:
    is_local = opts.local and target in LOCAL_NAMES
    address = "127.0.0.1" if is_local else resolve(target)
    host = HostResult(address=address or target, hostname="" if _is_ip(target) else target)
    findings: list[Finding] = []
    if address is None:
        host.errors.append("could not resolve hostname")
        return _HostOutcome(host, findings)

    public = is_public(address)
    ctx = CheckContext(timeout=opts.timeout, hostname=None if _is_ip(target) else target, public=public)

    open_ports: list[int] = []
    if opts.network:
        state = await scan_ports(address, opts.ports, opts.connect_timeout, sem)
        host.alive = state.alive
        open_ports = state.open
        udp_tasks = []
        if opts.udp and (host.alive or len(opts.targets) == 1):
            udp_services: list = []
            udp_tasks = [
                asyncio.ensure_future(_safe(reg.func(reg.info, address, udp_services, ctx), reg.info.id, host))
                for reg in checks.by_kind("host-network")
            ]
        if open_ports:
            progress(f"  {target}: {len(open_ports)} open port(s), fingerprinting")
            host.services = list(
                await asyncio.gather(*(fingerprint(address, p, opts.timeout) for p in open_ports))
            )
            findings += await _run_service_checks(host.services, ctx, host)
        if udp_tasks:
            udp_findings = [f for batch in await asyncio.gather(*udp_tasks) for f in batch]
            findings += udp_findings
            host.services += udp_services
            if udp_findings:
                host.alive = True

    runner = None
    if is_local:
        runner = LocalRunner(sudo=opts.sudo)
    elif opts.ssh and (not opts.network or opts.ssh_port in open_ports):
        runner = SSHRunner(
            host=target,
            user=opts.ssh_user,
            port=opts.ssh_port,
            key=opts.ssh_key,
            sudo=opts.sudo,
            strict_host_keys=opts.strict_host_keys,
            extra_options=opts.ssh_options,
        )
    elif opts.ssh and host.alive:
        host.notes.append(f"SSH port {opts.ssh_port} not open; credentialed checks skipped")

    inventory = None
    if runner is not None:
        progress(f"  {target}: collecting inventory ({runner.description})")
        try:
            result = await asyncio.to_thread(runner.run_script, COLLECTOR_SCRIPT)
            inventory = parse_collection(result.stdout)
            if not inventory.os_release and not inventory.packages:
                raise CollectionError(
                    "collection returned no data" + (f": {result.stderr.strip()[:200]}" if result.stderr else "")
                )
            host.credentialed = True
            host.alive = True
            host.os_name = inventory.os_name
            host.os_id = inventory.os_id
            host.os_version = inventory.os_version
            host.kernel = inventory.kernel
            host.package_count = len(inventory.packages)
            host.package_format = inventory.package_format
            if inventory.hostname and not host.hostname:
                host.hostname = inventory.hostname
            if inventory.uid != 0 and not result.used_sudo:
                host.notes.append(
                    "Collected without root: some configuration checks (firewall, shadow file) "
                    "were limited. Use --sudo for full coverage."
                )
            for reg in checks.by_kind("host-config"):
                try:
                    findings += reg.func(reg.info, inventory, host.address) or []
                except Exception as exc:  # noqa: BLE001
                    host.notes.append(f"check {reg.info.id} failed: {exc}")
        except CollectionError as exc:
            host.errors.append(str(exc))
    return _HostOutcome(host, findings, inventory)


async def _scan_all(targets: list[str], opts: ScanOptions, progress: Progress) -> list[_HostOutcome]:
    sem = asyncio.Semaphore(opts.concurrency)
    host_sem = asyncio.Semaphore(opts.host_concurrency)
    done = 0

    async def one(target: str) -> _HostOutcome:
        nonlocal done
        async with host_sem:
            try:
                outcome = await _scan_host(target, opts, sem, progress)
            except Exception as exc:  # noqa: BLE001
                outcome = _HostOutcome(HostResult(address=target), [])
                outcome.host.errors.append(f"internal error: {exc}")
                outcome.host.notes.append(traceback.format_exc(limit=3))
        done += 1
        h = outcome.host
        if h.alive or h.errors:
            status = "up" if h.alive else "error"
            extra = f", {len(h.services)} services" if h.services else ""
            if h.credentialed:
                extra += f", {h.package_count} packages"
            if h.errors:
                extra += f" ({h.errors[0]})"
            progress(f"[{done}/{len(targets)}] {target}: {status}{extra}")
        return outcome

    return list(await asyncio.gather(*(one(t) for t in targets)))


def _ensure_vulndb(db: VulnDB, outcomes: list[_HostOutcome], progress: Progress) -> list[str]:
    """Download advisory data for any distro release we found but have no data for."""
    notes = []
    missing_families = sorted(
        {
            key[0]
            for o in outcomes
            if o.inventory and (key := o.inventory.osv_key()) and not db.has_release(*key)
        }
    )
    if not missing_families:
        return notes
    progress(f"Fetching vulnerability data for: {', '.join(missing_families)} (first run only)")
    try:
        feeds.update_osv(db, missing_families)
        if not db.stats()["kev"]:
            feeds.update_kev(db)
        if not db.stats()["epss"]:
            try:
                feeds.update_epss(db)
            except feeds.FeedError as exc:
                notes.append(str(exc))
    except feeds.FeedError as exc:
        notes.append(f"{exc}. Run 'sightline db update' when you have connectivity.")
    return notes


def run_scan(
    opts: ScanOptions,
    progress: Progress | None = None,
    db_path=None,
    store: ScanStore | None = None,
    save: bool = True,
) -> ScanResult:
    progress = progress or (lambda _msg: None)
    targets = list(opts.targets)
    if opts.local and not any(t in LOCAL_NAMES for t in targets):
        targets.insert(0, "localhost")
    if not targets:
        raise ValueError("nothing to scan: give targets or --local")
    hosts = expand_targets(targets, opts.max_hosts)
    opts.targets = targets

    result = ScanResult(
        scan_id=new_scan_id(),
        name=opts.name or ", ".join(targets)[:80],
        targets=targets,
        started=_now(),
        options=opts.public_dict(),
    )
    progress(f"Scanning {len(hosts)} host(s), {len(opts.ports) if opts.network else 0} ports each")
    outcomes = asyncio.run(_scan_all(hosts, opts, progress))

    db = VulnDB(db_path or vulndb_path())
    try:
        if opts.auto_update_db and any(o.inventory for o in outcomes):
            for note in _ensure_vulndb(db, outcomes, progress):
                progress(f"  note: {note}")
        all_findings: list[Finding] = []
        for o in outcomes:
            findings = list(o.findings)
            if o.inventory is not None:
                pkg_findings, notes = match_inventory(db, o.inventory, o.host.address)
                o.host.notes.extend(notes)
                mark_exposure(pkg_findings, o.inventory)
                if pkg_findings or not notes:
                    # Package data is authoritative: drop banner guesses for this host.
                    findings = [
                        f for f in findings
                        if not (f.category == "network" and f.cves and f.confidence != "confirmed")
                    ]  # fmt: skip
                findings += pkg_findings
            all_findings += findings
            result.hosts.append(o.host)
        enrich(db, all_findings)
        kev_cves = set(db.kev_entries({c for f in all_findings for c in f.cves}))
        exploit_enrich(all_findings, kev_cves)
        result.vulndb = db.stats()
        result.vulndb.pop("releases", None)
    finally:
        db.close()

    public_hosts = {h.address for h in result.hosts if is_public(h.address)}
    result.findings = prioritize(all_findings, public_hosts)
    result.hosts.sort(key=lambda h: (not h.alive, _sort_addr(h.address)))
    result.finished = _now()

    own_store = store is None and save
    if own_store:
        store = ScanStore(scans_path())
    try:
        if store is not None:
            apply_diff(result, store.previous(result))
            if save:
                store.save(result)
        else:
            apply_diff(result, None)
    finally:
        if own_store and store is not None:
            store.close()
    return result


def _sort_addr(addr: str):
    try:
        ip = ipaddress.ip_address(addr)
        return (ip.version, int(ip), "")
    except ValueError:
        return (9, 0, addr)
