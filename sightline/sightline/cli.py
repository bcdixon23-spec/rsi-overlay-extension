"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sightline import __version__
from sightline.config import scans_path, vulndb_path
from sightline.models import SEVERITIES, severity_rank
from sightline.risk import PRIORITIES

EPILOG = "Only scan systems you own or have written permission to test."


def _err(msg: str) -> None:
    print(f"sightline: {msg}", file=sys.stderr)


def _progress(quiet: bool):
    if quiet:
        return lambda _m: None
    return lambda m: print(m, file=sys.stderr, flush=True)


def _write_reports(result, args) -> None:
    from sightline.report.export import to_csv, to_json
    from sightline.report.html import render_html

    for attr, render in (("html", render_html), ("json", to_json), ("csv", to_csv)):
        path = getattr(args, attr, None)
        if path:
            Path(path).write_text(render(result))
            print(f"{attr.upper()} report written to {path}", file=sys.stderr)


def _fail_on(result, level: str | None) -> int:
    if not level:
        return 0
    if level in PRIORITIES:
        cutoff = PRIORITIES.index(level)
        hit = any(PRIORITIES.index(f.priority) <= cutoff for f in result.findings if f.priority)
    else:
        cutoff = severity_rank(level)
        hit = any(severity_rank(f.severity) >= cutoff for f in result.findings if f.severity != "unknown")
    return 2 if hit else 0


# ---------------------------------------------------------------- commands


def cmd_scan(args) -> int:
    from sightline.netscan import parse_ports
    from sightline.report.console import render
    from sightline.scanner import ScanOptions, run_scan
    from sightline.targets import TargetError

    if not args.targets and not args.local:
        _err("give one or more targets (IP, CIDR, range, hostname, @file) or --local")
        return 1
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        _err(str(exc))
        return 1
    opts = ScanOptions(
        targets=args.targets,
        name=args.name or "",
        ports=ports,
        network=not args.no_network,
        udp=not args.no_udp,
        local=args.local,
        ssh=bool(args.ssh or args.ssh_user or args.ssh_key),
        ssh_user=args.ssh_user,
        ssh_key=args.ssh_key,
        ssh_port=args.ssh_port,
        ssh_options=args.ssh_option or [],
        sudo=args.sudo,
        strict_host_keys=args.strict_host_keys,
        timeout=args.timeout,
        connect_timeout=args.connect_timeout,
        concurrency=args.concurrency,
        max_hosts=args.max_hosts,
        auto_update_db=not args.offline,
    )
    try:
        result = run_scan(opts, progress=_progress(args.quiet), save=not args.no_save)
    except (TargetError, ValueError) as exc:
        _err(str(exc))
        return 1
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    if not args.quiet:
        render(result, limit=args.limit, verbose=args.verbose)
    _write_reports(result, args)
    if not args.no_save and not args.quiet:
        print(f"Saved as scan {result.scan_id}. View later with: sightline show {result.scan_id}", file=sys.stderr)
    return _fail_on(result, args.fail_on)


def _open_store():
    from sightline.storage import ScanStore

    return ScanStore(scans_path())


def cmd_history(args) -> int:
    store = _open_store()
    rows = store.list(args.limit)
    if not rows:
        print("No scans yet. Run: sightline scan <targets>")
        return 0
    print(f"{'SCAN ID':<22} {'STARTED':<20} {'HOSTS':>5} {'NOW':>4} {'SOON':>5} {'TOTAL':>6}  NAME")
    for r in rows:
        s = r["summary"]
        bp = s.get("by_priority", {})
        print(
            f"{r['id']:<22} {r['started'][:19]:<20} {s.get('hosts_alive', 0):>5} "
            f"{bp.get('fix-now', 0):>4} {bp.get('fix-soon', 0):>5} {s.get('findings', 0):>6}  {r['name'][:50]}"
        )
    return 0


def _load(scan_id: str):
    store = _open_store()
    result = store.get(scan_id)
    if result is None:
        _err(f"no scan matching {scan_id!r} (see: sightline history)")
    return result


def cmd_show(args) -> int:
    from sightline.report.console import render

    result = _load(args.scan_id)
    if result is None:
        return 1
    render(result, limit=args.limit, verbose=args.verbose)
    return 0


def cmd_report(args) -> int:
    result = _load(args.scan_id)
    if result is None:
        return 1
    if not (args.html or args.json or args.csv):
        _err("choose at least one of --html, --json, --csv")
        return 1
    _write_reports(result, args)
    return 0


def cmd_diff(args) -> int:
    from sightline.storage import apply_diff

    store = _open_store()
    new = store.get(args.new)
    if new is None:
        _err("no scans to compare")
        return 1
    old = store.get(args.old) if args.old else store.previous(new)
    if old is None:
        _err("no earlier scan of the same targets to compare against")
        return 1
    apply_diff(new, old)
    added = [f for f in new.findings if f.status == "new"]
    print(f"Comparing {old.scan_id} -> {new.scan_id}")
    print(f"  new: {len(added)}   fixed: {len(new.fixed)}   unchanged: {len(new.findings) - len(added)}")
    for f in added[: args.limit]:
        print(f"  + [{f.severity:<8}] {f.host:<15} {f.title[:80]}")
    for f in new.fixed[: args.limit]:
        print(f"  - [{f.severity:<8}] {f.host:<15} {f.title[:80]}")
    return 0


def cmd_checks(args) -> int:
    from sightline import checks

    regs = checks.load_all()
    kinds = {"service": "network", "host-network": "network", "host-config": "host config"}
    print(f"{len(regs)} checks (+ package vulnerability matching against distro advisories)\n")
    for r in sorted(regs, key=lambda r: (r.kind == "host-config", r.info.id)):
        print(f"  {r.info.id:<32} {r.info.severity:<9} {kinds[r.kind]:<12} {r.info.title}")
    return 0


def cmd_db(args) -> int:
    from sightline.vulndb import feeds
    from sightline.vulndb.store import FAMILY_TO_OSV, VulnDB

    db = VulnDB(vulndb_path())
    try:
        if args.db_cmd == "status":
            s = db.stats()
            print(f"Database: {db.path}")
            print(f"  advisories: {s['advisories']}  (updated {s['osv_updated'] or 'never'})")
            print(f"  CISA KEV:   {s['kev']}  (updated {s['kev_updated'] or 'never'})")
            print(f"  EPSS:       {s['epss']}  (updated {s['epss_updated'] or 'never'})")
            if s["releases"]:
                print("  releases covered:")
                for fam, rel, n in s["releases"]:
                    print(f"    {fam:<10} {rel:<8} {n} advisories")
            return 0
        if args.db_cmd == "update":
            families = args.families or sorted({fam for fam, _, _ in db.releases()}) or []
            if not families:
                _err(
                    "which distro families? e.g. 'sightline db update ubuntu debian' "
                    f"(available: {', '.join(FAMILY_TO_OSV)}). A credentialed scan fetches "
                    "what it needs automatically."
                )
                return 1
            try:
                feeds.update_osv(db, families)
                if not args.no_kev:
                    feeds.update_kev(db)
                if not args.no_epss:
                    feeds.update_epss(db)
            except feeds.FeedError as exc:
                _err(str(exc))
                return 1
            return 0
        if args.db_cmd == "import":
            total = 0
            for p in args.paths:
                path = Path(p)
                is_bundle = path.is_dir() and any(
                    any(path.glob(pattern)) for pattern in ("*.zip", "known_exploited*", "epss*")
                )
                if is_bundle:
                    counts = feeds.import_offline_bundle(db, path)
                    print(f"{path}: {counts}")
                    total += counts["osv"]
                else:
                    n = db.import_path(path)
                    print(f"{path}: {n} advisories")
                    total += n
            if total:
                db.touch("osv_updated")
            return 0
        if args.db_cmd == "bundle":
            saved = feeds.download_bundle(Path(args.directory), args.families)
            print("Saved:\n  " + "\n  ".join(str(s) for s in saved))
            print(f"Copy {args.directory} to the offline host and run: sightline db import {args.directory}")
            return 0
    finally:
        db.close()
    return 1


def cmd_serve(args) -> int:
    from sightline.web.server import serve

    return serve(args.host, args.port, args.token)


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sightline",
        description="Agentless vulnerability and exposure scanner for Linux servers and networks.",
        epilog=EPILOG,
    )
    p.add_argument("--version", action="version", version=f"sightline {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan hosts and networks", epilog=EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter,
                       description="Examples:\n"
                       "  sightline scan 192.168.1.0/24\n"
                       "  sightline scan --local\n"
                       "  sightline scan web01 db01 --ssh-user ops --ssh-key ~/.ssh/id_ed25519 --sudo\n"
                       "  sightline scan @hosts.txt --html report.html --fail-on fix-now")  # fmt: skip
    s.add_argument("targets", nargs="*", help="IPs, CIDRs, ranges (10.0.0.1-50), hostnames, or @file")
    g = s.add_argument_group("credentialed scanning")
    g.add_argument("--local", action="store_true", help="also run a credentialed scan of this machine")
    g.add_argument("--ssh", action="store_true", help="collect over SSH using your ~/.ssh/config defaults")
    g.add_argument("--ssh-user", help="SSH user for credentialed collection")
    g.add_argument("--ssh-key", help="SSH private key file")
    g.add_argument("--ssh-port", type=int, default=22)
    g.add_argument("--ssh-option", action="append", metavar="OPT", help="extra ssh -o option (repeatable)")
    g.add_argument("--sudo", action="store_true", help="collect with 'sudo -n' for full config coverage")
    g.add_argument("--strict-host-keys", action="store_true",
                   help="refuse unknown SSH host keys (default: accept new, reject changed)")
    g = s.add_argument_group("network scanning")
    g.add_argument("--ports", default="default", help="'default', 'all', or a list like 22,80,8000-8100")
    g.add_argument("--no-network", action="store_true", help="skip port scanning (credentialed only)")
    g.add_argument("--no-udp", action="store_true", help="skip the SNMP UDP probe")
    g.add_argument("--timeout", type=float, default=3.0, help="per-probe timeout for service checks")
    g.add_argument("--connect-timeout", type=float, default=1.0, help="TCP connect timeout for discovery")
    g.add_argument("--concurrency", type=int, default=400, help="max simultaneous connections")
    g.add_argument("--max-hosts", type=int, default=4096)
    g = s.add_argument_group("output")
    g.add_argument("--name", help="label for this scan (used to compare with earlier runs)")
    g.add_argument("--html", metavar="PATH", help="write an HTML report")
    g.add_argument("--json", metavar="PATH", help="write a JSON report")
    g.add_argument("--csv", metavar="PATH", help="write findings as CSV")
    g.add_argument("--limit", type=int, default=15, help="findings to print per section")
    g.add_argument("--fail-on", choices=list(PRIORITIES) + list(SEVERITIES[:4]),
                   help="exit with status 2 if any finding is at or above this level (for CI)")
    g.add_argument("--no-save", action="store_true", help="don't store the scan in history")
    g.add_argument("--offline", action="store_true", help="never download vulnerability data")
    g.add_argument("-q", "--quiet", action="store_true")
    g.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_scan)

    h = sub.add_parser("history", help="list previous scans")
    h.add_argument("--limit", type=int, default=20)
    h.set_defaults(func=cmd_history)

    sh = sub.add_parser("show", help="print a stored scan")
    sh.add_argument("scan_id", nargs="?", default="latest")
    sh.add_argument("--limit", type=int, default=15)
    sh.add_argument("-v", "--verbose", action="store_true")
    sh.set_defaults(func=cmd_show)

    r = sub.add_parser("report", help="export a stored scan")
    r.add_argument("scan_id", nargs="?", default="latest")
    r.add_argument("--html")
    r.add_argument("--json")
    r.add_argument("--csv")
    r.set_defaults(func=cmd_report)

    d = sub.add_parser("diff", help="compare two scans (default: latest vs the one before)")
    d.add_argument("old", nargs="?")
    d.add_argument("new", nargs="?", default="latest")
    d.add_argument("--limit", type=int, default=50)
    d.set_defaults(func=cmd_diff)

    c = sub.add_parser("checks", help="list built-in checks")
    c.set_defaults(func=cmd_checks)

    db = sub.add_parser("db", help="manage the local vulnerability database")
    dbs = db.add_subparsers(dest="db_cmd", required=True)
    dbs.add_parser("status", help="show what data is loaded")
    u = dbs.add_parser("update", help="download/refresh advisories, KEV and EPSS")
    u.add_argument("families", nargs="*", help="ubuntu debian alpine rocky almalinux redhat")
    u.add_argument("--no-kev", action="store_true")
    u.add_argument("--no-epss", action="store_true")
    i = dbs.add_parser("import", help="import OSV files/zips or an offline bundle directory")
    i.add_argument("paths", nargs="+")
    b = dbs.add_parser("bundle", help="download feeds to a directory for air-gapped hosts")
    b.add_argument("directory")
    b.add_argument("families", nargs="+")
    db.set_defaults(func=cmd_db)

    w = sub.add_parser("serve", help="run the web dashboard")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8077)
    w.add_argument("--token", help="access token (generated automatically when not on localhost)")
    w.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
