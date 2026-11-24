"""Download vulnerability feeds into the local database.

Sources (all free, no account needed):
  * OSV.dev bulk exports - distro security advisories with exact fixed versions
  * CISA Known Exploited Vulnerabilities (KEV) catalog
  * FIRST EPSS - probability a CVE is exploited in the next 30 days
"""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from sightline.config import USER_AGENT
from sightline.vulndb.store import FAMILY_TO_OSV, VulnDB

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URLS = [
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
]


class FeedError(RuntimeError):
    pass


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _download(url: str, dest: Path, timeout: int = 120) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, dest.open("wb") as fh:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            last_pct = -10
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if total and sys.stderr.isatty():
                    pct = int(done * 100 / total)
                    if pct >= last_pct + 10:
                        last_pct = pct
                        _log(f"    {pct:3d}%  {done / 1e6:.1f} MB")
    except Exception as exc:  # urllib raises a zoo of exception types
        raise FeedError(f"download failed for {url}: {exc}") from exc


def osv_url(family: str) -> str:
    name = FAMILY_TO_OSV[family]
    return f"{OSV_BUCKET}/{urllib.parse.quote(name)}/all.zip"


def update_osv(db: VulnDB, families: list[str], releases: set[tuple[str, str]] | None = None) -> int:
    total = 0
    with tempfile.TemporaryDirectory(prefix="sightline-") as tmp:
        for family in families:
            if family not in FAMILY_TO_OSV:
                raise FeedError(
                    f"unknown distro family {family!r}; choose from {', '.join(FAMILY_TO_OSV)}"
                )
            url = osv_url(family)
            dest = Path(tmp) / f"{family}.zip"
            _log(f"  downloading {FAMILY_TO_OSV[family]} advisories from OSV.dev ...")
            _download(url, dest)
            _log("  importing ...")
            wanted = {r for r in releases if r[0] == family} if releases else None
            n = db.import_path(dest, families={family}, releases=wanted or None)
            _log(f"  {n} advisories imported for {family}")
            total += n
            dest.unlink(missing_ok=True)
    db.touch("osv_updated")
    return total


def update_kev(db: VulnDB) -> int:
    with tempfile.TemporaryDirectory(prefix="sightline-") as tmp:
        dest = Path(tmp) / "kev.json"
        _log("  downloading CISA Known Exploited Vulnerabilities catalog ...")
        _download(KEV_URL, dest)
        n = db.import_kev(json.loads(dest.read_text()))
    db.touch("kev_updated")
    _log(f"  {n} known-exploited CVEs loaded")
    return n


def update_epss(db: VulnDB) -> int:
    last_error: Exception | None = None
    with tempfile.TemporaryDirectory(prefix="sightline-") as tmp:
        dest = Path(tmp) / "epss.csv.gz"
        for url in EPSS_URLS:
            try:
                _log("  downloading EPSS exploit-probability scores ...")
                _download(url, dest)
                with gzip.open(dest, "rt") as fh:
                    n = db.import_epss_csv(fh)
                db.touch("epss_updated")
                _log(f"  {n} EPSS scores loaded")
                return n
            except (FeedError, OSError) as exc:
                last_error = exc
    raise FeedError(f"could not fetch EPSS data: {last_error}")


def import_offline_bundle(db: VulnDB, directory: Path) -> dict[str, int]:
    """Load feeds from a directory copied in from a connected machine.

    Expected files (any subset): *.zip (OSV exports), known_exploited_vulnerabilities.json,
    epss_scores-current.csv.gz
    """
    counts = {"osv": 0, "kev": 0, "epss": 0}
    for path in sorted(directory.iterdir()):
        if path.suffix == ".zip":
            counts["osv"] += db.import_path(path)
        elif path.name.startswith("known_exploited") and path.suffix == ".json":
            counts["kev"] = db.import_kev(json.loads(path.read_text()))
        elif path.name.startswith("epss") and path.name.endswith(".gz"):
            with gzip.open(path, "rt") as fh:
                counts["epss"] = db.import_epss_csv(fh)
        elif path.name.startswith("epss") and path.suffix == ".csv":
            with path.open() as fh:
                counts["epss"] = db.import_epss_csv(fh)
    if counts["osv"]:
        db.touch("osv_updated")
    if counts["kev"]:
        db.touch("kev_updated")
    if counts["epss"]:
        db.touch("epss_updated")
    return counts


def download_bundle(directory: Path, families: list[str]) -> list[Path]:
    """Fetch raw feed files for later offline import on an air-gapped host."""
    directory.mkdir(parents=True, exist_ok=True)
    saved = []
    for family in families:
        dest = directory / f"osv-{family}.zip"
        _log(f"  downloading {FAMILY_TO_OSV[family]} ...")
        _download(osv_url(family), dest)
        saved.append(dest)
    kev = directory / "known_exploited_vulnerabilities.json"
    _download(KEV_URL, kev)
    saved.append(kev)
    epss = directory / "epss_scores-current.csv.gz"
    for url in EPSS_URLS:
        try:
            _download(url, epss)
            saved.append(epss)
            break
        except FeedError:
            continue
    return saved


__all__ = [
    "FeedError",
    "update_osv",
    "update_kev",
    "update_epss",
    "import_offline_bundle",
    "download_bundle",
    "osv_url",
]
