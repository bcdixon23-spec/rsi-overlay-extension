"""Machine-readable exports."""

from __future__ import annotations

import csv
import io
import json

from sightline.models import ScanResult

CSV_FIELDS = [
    "priority", "risk", "severity", "status", "host", "port", "category", "check_id", "title",
    "package", "installed_version", "fixed_version", "advisory", "cves", "cvss", "epss", "kev",
    "exposed", "confidence", "evidence", "remediation",
]  # fmt: skip


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in result.findings:
        row = f.to_dict()
        row["cves"] = " ".join(f.cves)
        writer.writerow(row)
    return buf.getvalue()
