"""Local vulnerability database built from OSV.dev data, CISA KEV and EPSS.

Everything is kept in one SQLite file so scans work fully offline and your
package inventory never leaves your network.
"""

from __future__ import annotations

import json
import re
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from sightline.models import severity_from_score
from sightline.vulndb import cvss

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# OSV ecosystem family name -> Sightline family key
FAMILIES = {
    "Ubuntu": "ubuntu",
    "Debian": "debian",
    "Alpine": "alpine",
    "Rocky Linux": "rocky",
    "AlmaLinux": "almalinux",
    "Red Hat": "redhat",
}
FAMILY_TO_OSV = {v: k for k, v in FAMILIES.items()}

_LABELS = {
    "critical": "critical",
    "important": "high",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "negligible": "low",
    "unimportant": "low",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
  id TEXT PRIMARY KEY,
  summary TEXT,
  details TEXT,
  cves TEXT,
  severity TEXT,
  cvss REAL,
  cvss_vector TEXT,
  published TEXT,
  modified TEXT,
  refs TEXT
);
CREATE TABLE IF NOT EXISTS affected (
  adv_id TEXT NOT NULL,
  family TEXT NOT NULL,
  release TEXT NOT NULL,
  variant TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  package TEXT NOT NULL,
  ranges TEXT,
  versions TEXT
);
CREATE INDEX IF NOT EXISTS affected_lookup ON affected(family, release, package);
CREATE INDEX IF NOT EXISTS affected_adv ON affected(adv_id);
CREATE TABLE IF NOT EXISTS kev (
  cve TEXT PRIMARY KEY,
  date_added TEXT,
  due_date TEXT,
  name TEXT,
  ransomware TEXT,
  action TEXT
);
CREATE TABLE IF NOT EXISTS epss (
  cve TEXT PRIMARY KEY,
  score REAL,
  percentile REAL
);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT
);
"""


def parse_ecosystem(ecosystem: str) -> tuple[str, str, str] | None:
    """Normalise an OSV ecosystem string to (family, release, variant).

    'Ubuntu:22.04:LTS'                -> ('ubuntu', '22.04', '')
    'Ubuntu:Pro:18.04:LTS'            -> ('ubuntu', '18.04', 'pro')
    'Debian:12'                       -> ('debian', '12', '')
    'Alpine:v3.19'                    -> ('alpine', '3.19', '')
    'Rocky Linux:9'                   -> ('rocky', '9', '')
    'Red Hat:enterprise_linux:9::appstream' -> ('redhat', '9', '')
    """
    parts = ecosystem.split(":")
    family = FAMILIES.get(parts[0])
    if not family or len(parts) < 2:
        return None
    rest = parts[1:]
    lowered = [p.lower() for p in rest]
    if any("fips" in p for p in lowered):
        return None
    variant = "pro" if "pro" in lowered else ""
    if family == "ubuntu":
        release = next((p for p in rest if re.fullmatch(r"\d+\.\d+", p)), "")
    elif family == "alpine":
        m = re.fullmatch(r"v?(\d+\.\d+)", rest[0])
        release = m.group(1) if m else ""
    elif family == "redhat":
        joined = ":".join(rest)
        if re.search(r"_(eus|aus|e4s|tus)\b", joined):
            return None
        m = re.search(r"(?<![\d.])(\d+)(?:\.\d+)?(?![\d.])", joined)
        release = m.group(1) if m else ""
    else:
        m = re.match(r"(\d+)", rest[0])
        release = m.group(1) if m else ""
    if not release:
        return None
    return family, release, variant


def _severity(record: dict) -> tuple[str, float | None, str]:
    label = ""
    best_score: float | None = None
    vector = ""
    for sev in record.get("severity") or []:
        kind = sev.get("type", "")
        value = str(sev.get("score", ""))
        if kind.startswith("CVSS"):
            s = cvss.score(value)
            if s is not None and (best_score is None or kind == "CVSS_V3"):
                best_score, vector = s, value
        elif value.lower() in _LABELS:
            label = _LABELS[value.lower()]
    if not label:
        for source in [record.get("database_specific") or {}] + [
            a.get("ecosystem_specific") or {} for a in record.get("affected", [])
        ]:
            raw = str(source.get("severity") or source.get("urgency") or "").lower()
            raw = raw.split()[0] if raw else ""
            if raw in _LABELS:
                label = _LABELS[raw]
                break
    if not label:
        label = severity_from_score(best_score)
    return label, best_score, vector


def _cves(record: dict) -> list[str]:
    found: list[str] = []
    fields = [record.get("id", "")] + list(record.get("aliases") or []) + list(
        record.get("upstream") or []
    )
    if not CVE_RE.search(record.get("id", "")):
        fields += list(record.get("related") or [])
    for value in fields:
        for cve in CVE_RE.findall(str(value)):
            if cve not in found:
                found.append(cve)
    return found


class VulnDB:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # ----------------------------------------------------------- importing

    def import_records(
        self,
        records: Iterable[dict],
        families: set[str] | None = None,
        releases: set[tuple[str, str]] | None = None,
    ) -> int:
        """Import OSV records. Returns the number of advisories stored."""
        count = 0
        cur = self.conn.cursor()
        for record in records:
            if record.get("withdrawn"):
                continue
            rows = []
            for aff in record.get("affected") or []:
                pkg = aff.get("package") or {}
                parsed = parse_ecosystem(pkg.get("ecosystem", ""))
                if not parsed or not pkg.get("name"):
                    continue
                family, release, variant = parsed
                if families and family not in families:
                    continue
                if releases and (family, release) not in releases:
                    continue
                ranges = [
                    r.get("events", [])
                    for r in aff.get("ranges") or []
                    if r.get("type") in ("ECOSYSTEM", "SEMVER")
                ]
                versions = aff.get("versions") or []
                if not ranges and not versions:
                    continue
                rows.append(
                    (
                        record["id"],
                        family,
                        release,
                        variant,
                        pkg["ecosystem"],
                        pkg["name"],
                        json.dumps(ranges) if ranges else None,
                        json.dumps(versions) if versions and not ranges else None,
                    )
                )
            if not rows:
                continue
            severity, score, vector = _severity(record)
            refs = [r.get("url") for r in record.get("references") or [] if r.get("url")]
            cur.execute("DELETE FROM affected WHERE adv_id = ?", (record["id"],))
            cur.execute(
                "INSERT OR REPLACE INTO advisories VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    record["id"],
                    (record.get("summary") or "")[:500],
                    (record.get("details") or "")[:4000],
                    json.dumps(_cves(record)),
                    severity,
                    score,
                    vector,
                    record.get("published", ""),
                    record.get("modified", ""),
                    json.dumps(refs[:8]),
                ),
            )
            cur.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?,?,?)", rows)
            count += 1
        self.conn.commit()
        return count

    def import_path(self, path: Path | str, **filters) -> int:
        """Import a single OSV .json file, a directory of them, or an OSV all.zip."""
        path = Path(path)
        if path.is_dir():
            return self.import_records(_iter_dir(path), **filters)
        if path.suffix == ".zip":
            return self.import_records(_iter_zip(path), **filters)
        data = json.loads(path.read_text())
        records = data if isinstance(data, list) else [data]
        return self.import_records(records, **filters)

    def import_kev(self, data: dict) -> int:
        rows = [
            (
                v.get("cveID"),
                v.get("dateAdded", ""),
                v.get("dueDate", ""),
                v.get("vulnerabilityName", ""),
                v.get("knownRansomwareCampaignUse", ""),
                v.get("requiredAction", ""),
            )
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        ]
        self.conn.execute("DELETE FROM kev")
        self.conn.executemany("INSERT OR REPLACE INTO kev VALUES (?,?,?,?,?,?)", rows)
        self.conn.commit()
        return len(rows)

    def import_epss_csv(self, lines: Iterable[str]) -> int:
        rows = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("cve,"):
                continue
            parts = line.split(",")
            if len(parts) < 3:
                continue
            try:
                rows.append((parts[0], float(parts[1]), float(parts[2])))
            except ValueError:
                continue
        self.conn.execute("DELETE FROM epss")
        self.conn.executemany("INSERT OR REPLACE INTO epss VALUES (?,?,?)", rows)
        self.conn.commit()
        return len(rows)

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, value))
        self.conn.commit()

    def get_meta(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def touch(self, key: str) -> None:
        self.set_meta(key, datetime.now(timezone.utc).isoformat(timespec="seconds"))

    # ------------------------------------------------------------- queries

    def candidates(self, family: str, release: str, names: Iterable[str]) -> list[sqlite3.Row]:
        names = list(dict.fromkeys(names))
        rows: list[sqlite3.Row] = []
        for i in range(0, len(names), 500):
            chunk = names[i : i + 500]
            marks = ",".join("?" * len(chunk))
            rows.extend(
                self.conn.execute(
                    f"""SELECT a.*, v.summary, v.details, v.cves, v.severity, v.cvss,
                               v.cvss_vector, v.refs
                        FROM affected a JOIN advisories v ON v.id = a.adv_id
                        WHERE a.family = ? AND a.release = ? AND a.package IN ({marks})""",
                    [family, release, *chunk],
                ).fetchall()
            )
        return rows

    def kev_entries(self, cves: Iterable[str]) -> dict[str, sqlite3.Row]:
        cves = list(cves)
        if not cves:
            return {}
        marks = ",".join("?" * len(cves))
        return {
            r["cve"]: r
            for r in self.conn.execute(f"SELECT * FROM kev WHERE cve IN ({marks})", cves)
        }

    def epss_scores(self, cves: Iterable[str]) -> dict[str, float]:
        cves = list(cves)
        if not cves:
            return {}
        marks = ",".join("?" * len(cves))
        return {
            r["cve"]: r["score"]
            for r in self.conn.execute(f"SELECT cve, score FROM epss WHERE cve IN ({marks})", cves)
        }

    def releases(self) -> list[tuple[str, str, int]]:
        return [
            (r[0], r[1], r[2])
            for r in self.conn.execute(
                "SELECT family, release, COUNT(DISTINCT adv_id) FROM affected "
                "GROUP BY family, release ORDER BY family, release"
            )
        ]

    def has_release(self, family: str, release: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM affected WHERE family = ? AND release = ? LIMIT 1", (family, release)
        ).fetchone()
        return row is not None

    def stats(self) -> dict:
        one = lambda q: self.conn.execute(q).fetchone()[0]  # noqa: E731
        return {
            "advisories": one("SELECT COUNT(*) FROM advisories"),
            "kev": one("SELECT COUNT(*) FROM kev"),
            "epss": one("SELECT COUNT(*) FROM epss"),
            "releases": self.releases(),
            "osv_updated": self.get_meta("osv_updated"),
            "kev_updated": self.get_meta("kev_updated"),
            "epss_updated": self.get_meta("epss_updated"),
        }


def _iter_dir(path: Path) -> Iterator[dict]:
    for file in sorted(path.rglob("*.json")):
        try:
            yield json.loads(file.read_text())
        except (OSError, json.JSONDecodeError):
            continue


def _iter_zip(path: Path) -> Iterator[dict]:
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                yield json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
