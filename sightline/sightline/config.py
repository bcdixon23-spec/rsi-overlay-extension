"""Paths and runtime settings."""

from __future__ import annotations

import os
from pathlib import Path

from sightline import __version__

USER_AGENT = f"sightline-scanner/{__version__}"


def data_dir() -> Path:
    base = os.environ.get("SIGHTLINE_HOME")
    path = Path(base).expanduser() if base else Path.home() / ".sightline"
    path.mkdir(parents=True, exist_ok=True)
    return path


def vulndb_path() -> Path:
    return data_dir() / "vulndb.sqlite"


def scans_path() -> Path:
    return data_dir() / "scans.sqlite"
