import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Never touch the real ~/.sightline during tests."""
    monkeypatch.setenv("SIGHTLINE_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def osv(id, ecosystem, package, events=None, versions=None, severity=None, aliases=(),
        related=(), summary="", db_specific=None):  # fmt: skip
    """Build a minimal OSV record."""
    affected = {"package": {"ecosystem": ecosystem, "name": package}}
    if events is not None:
        affected["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
    if versions is not None:
        affected["versions"] = versions
    rec = {
        "id": id,
        "summary": summary or f"{package} issue",
        "details": f"Details for {id}",
        "aliases": list(aliases),
        "related": list(related),
        "affected": [affected],
        "references": [{"type": "ADVISORY", "url": f"https://example.test/{id}"}],
    }
    if severity:
        rec["severity"] = severity
    if db_specific:
        rec["database_specific"] = db_specific
    return rec
