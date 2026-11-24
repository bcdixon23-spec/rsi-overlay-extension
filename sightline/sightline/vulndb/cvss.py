"""CVSS base score calculation from vector strings (v3.0, v3.1 and v2)."""

from __future__ import annotations

import math

_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_V3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}

_V2 = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
    "CIA": {"N": 0.0, "P": 0.275, "C": 0.660},
}


def _roundup(value: float) -> float:
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def _parse(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    return metrics


def score_v3(vector: str) -> float | None:
    m = _parse(vector)
    try:
        scope = m["S"]
        av = _V3["AV"][m["AV"]]
        ac = _V3["AC"][m["AC"]]
        pr = _V3_PR[scope][m["PR"]]
        ui = _V3["UI"][m["UI"]]
        c, i, a = (_V3["CIA"][m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def score_v2(vector: str) -> float | None:
    m = _parse(vector.replace("(", "").replace(")", ""))
    try:
        av = _V2["AV"][m["AV"]]
        ac = _V2["AC"][m["AC"]]
        au = _V2["Au"][m["Au"]]
        c, i, a = (_V2["CIA"][m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    exploitability = 20 * av * ac * au
    f = 0 if impact == 0 else 1.176
    return round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * f, 1)


def score(vector: str) -> float | None:
    """Return the base score for a CVSS vector, or None if unsupported."""
    if not vector:
        return None
    if vector.startswith("CVSS:3"):
        return score_v3(vector)
    if vector.startswith("CVSS:4"):
        return None  # v4 needs the full macro-vector lookup tables
    if "Au:" in vector:
        return score_v2(vector)
    return None
