"""Scan history in SQLite, plus diffing between scans."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from sightline.models import Finding, ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  name TEXT,
  started TEXT,
  finished TEXT,
  targets TEXT,
  summary TEXT,
  data TEXT
);
CREATE INDEX IF NOT EXISTS scans_started ON scans(started);
"""


class ScanStore:
    def __init__(self, path: Path | str):
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def save(self, result: ScanResult) -> None:
        data = result.to_dict()
        self.conn.execute(
            "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?)",
            (
                result.scan_id,
                result.name,
                result.started,
                result.finished,
                json.dumps(result.targets),
                json.dumps(data["summary"]),
                json.dumps(data),
            ),
        )
        self.conn.commit()

    def get(self, scan_id: str) -> ScanResult | None:
        if scan_id in ("latest", "last"):
            row = self.conn.execute("SELECT data FROM scans ORDER BY started DESC LIMIT 1").fetchone()
        else:
            row = self.conn.execute(
                "SELECT data FROM scans WHERE id = ? OR id LIKE ? ORDER BY started DESC LIMIT 1",
                (scan_id, scan_id + "%"),
            ).fetchone()
        return ScanResult.from_dict(json.loads(row["data"])) if row else None

    def list(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, name, started, finished, targets, summary FROM scans "
            "ORDER BY started DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "started": r["started"],
                "finished": r["finished"],
                "targets": json.loads(r["targets"]),
                "summary": json.loads(r["summary"]),
            }
            for r in rows
        ]

    def previous(self, result: ScanResult) -> ScanResult | None:
        """The most recent earlier scan of the same targets (or the same name)."""
        rows = self.conn.execute(
            "SELECT id, name, targets FROM scans WHERE started <= ? AND id != ? "
            "ORDER BY started DESC, rowid DESC",
            (result.started, result.scan_id),
        ).fetchall()
        targets = sorted(result.targets)
        for row in rows:
            if sorted(json.loads(row["targets"])) == targets or (
                result.name and row["name"] == result.name
            ):
                return self.get(row["id"])
        return None

    def delete(self, scan_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self.conn.commit()
        return cur.rowcount > 0


def apply_diff(current: ScanResult, previous: ScanResult | None) -> None:
    """Mark findings new/existing and list findings that disappeared (fixed)."""
    if previous is None:
        for f in current.findings:
            f.status = "new"
        current.fixed = []
        current.previous_scan_id = None
        return
    current.previous_scan_id = previous.scan_id
    old_keys = {f.key for f in previous.findings}
    for f in current.findings:
        f.status = "existing" if f.key in old_keys else "new"

    # Only call a finding fixed if we looked at that host the same way this time.
    now_alive = {h.address for h in current.hosts if h.alive or h.credentialed}
    now_cred = {h.address for h in current.hosts if h.credentialed}
    new_keys = {f.key for f in current.findings}
    fixed: list[Finding] = []
    for f in previous.findings:
        if f.key in new_keys or f.host not in now_alive:
            continue
        if f.category in ("package", "config") and f.host not in now_cred:
            continue
        f.status = "fixed"
        fixed.append(f)
    current.fixed = fixed
