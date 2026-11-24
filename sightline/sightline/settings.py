"""User-customisable settings, so the tool feels like *yours*.

Stored as JSON in ~/.sightline/config.json (override the directory with
SIGHTLINE_HOME). Everything has a sensible default, so the file is optional.
The organisation name, accent colour and tagline flow into every report and
into the dashboard, and the scan defaults save repeating the same flags.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from sightline.config import data_dir

_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
THEMES = ("auto", "light", "dark")
ACCENT_PRESETS = {
    "blue": "#3355dd", "indigo": "#4f46e5", "violet": "#7c3aed", "teal": "#0d9488",
    "green": "#1f8a4c", "amber": "#d97706", "red": "#dc2626", "slate": "#475569",
    "cyan": "#0891b2", "pink": "#db2777",
}  # fmt: skip


@dataclass
class Settings:
    org_name: str = "Sightline"
    tagline: str = "Agentless vulnerability and exposure scanning"
    accent: str = "#3355dd"
    theme: str = "auto"  # auto | light | dark
    analyst: str = ""  # shown as "prepared by" on reports
    show_glossary: bool = True  # include the plain-language help section in reports
    beginner_mode: bool = True  # expand explanations by default
    default_ports: str = "default"
    default_ssh_user: str = ""
    default_sudo: bool = False
    emoji: bool = True

    def normalised(self) -> "Settings":
        s = Settings(**{f.name: getattr(self, f.name) for f in fields(self)})
        s.org_name = (s.org_name or "Sightline").strip()[:60]
        s.tagline = (s.tagline or "").strip()[:120]
        s.analyst = (s.analyst or "").strip()[:60]
        accent = (s.accent or "").strip().lower()
        accent = ACCENT_PRESETS.get(accent, accent)
        s.accent = accent if _HEX.match(accent) else Settings.accent
        s.theme = s.theme if s.theme in THEMES else "auto"
        return s

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Settings":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in known}).normalised()


def config_path() -> Path:
    return data_dir() / "config.json"


def load() -> Settings:
    path = config_path()
    if path.is_file():
        try:
            return Settings.from_dict(json.loads(path.read_text()))
        except (OSError, ValueError, TypeError):
            pass
    return Settings()


def save(settings: Settings) -> Path:
    path = config_path()
    path.write_text(json.dumps(settings.normalised().to_dict(), indent=2))
    return path


def update(**changes) -> Settings:
    current = load()
    data = current.to_dict()
    for key, value in changes.items():
        if value is not None and key in data:
            data[key] = value
    settings = Settings.from_dict(data)
    save(settings)
    return settings
