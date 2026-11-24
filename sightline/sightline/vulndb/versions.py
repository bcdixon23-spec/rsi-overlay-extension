"""Distribution package version comparison.

Getting this right is what lets Sightline avoid the classic scanner false
positive: a distro ships "OpenSSH 8.9p1" with years of backported fixes, and
only its packaging version (8.9p1-3ubuntu0.10) tells you whether a fix is in.

Implements:
  * dpkg   (Debian, Ubuntu and derivatives) - Debian Policy 5.6.12
  * rpm    (RHEL, Rocky, AlmaLinux, Fedora, SUSE) - rpmvercmp incl. ~ and ^
  * apk    (Alpine) - number/letter/suffix/revision ordering
"""

from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Callable

_DIGITS = "0123456789"
_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


# --------------------------------------------------------------------- dpkg


def _dpkg_order(c: str) -> int:
    if not c or c in _DIGITS:
        return 0
    if c in _LETTERS:
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and a[i] not in _DIGITS) or (j < lb and b[j] not in _DIGITS):
            ac = _dpkg_order(a[i]) if i < la else 0
            bc = _dpkg_order(b[j]) if j < lb else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and a[i] in _DIGITS and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i] in _DIGITS:
            return 1
        if j < lb and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_split(version: str) -> tuple[int, str, str]:
    version = version.strip()
    epoch = 0
    if ":" in version:
        e, version = version.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in version:
        upstream, revision = version.rsplit("-", 1)
    else:
        upstream, revision = version, ""
    return epoch, upstream, revision


def compare_dpkg(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return _sign(ea - eb)
    c = _verrevcmp(ua, ub)
    if c:
        return _sign(c)
    return _sign(_verrevcmp(ra, rb))


# ---------------------------------------------------------------------- rpm


def _isalnum(c: str) -> bool:
    return c in _DIGITS or c in _LETTERS


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not _isalnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < lb and not _isalnum(b[j]) and b[j] not in "~^":
            j += 1

        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue

        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue

        if not (i < la and j < lb):
            break

        si, sj = i, j
        if a[i] in _DIGITS:
            while i < la and a[i] in _DIGITS:
                i += 1
            while j < lb and b[j] in _DIGITS:
                j += 1
            isnum = True
        else:
            while i < la and a[i] in _LETTERS:
                i += 1
            while j < lb and b[j] in _LETTERS:
                j += 1
            isnum = False

        seg1, seg2 = a[si:i], b[sj:j]
        if not seg2:
            # Segment types differ: a numeric segment is always newer.
            return 1 if isnum else -1
        if isnum:
            seg1 = seg1.lstrip("0")
            seg2 = seg2.lstrip("0")
            if len(seg1) != len(seg2):
                return 1 if len(seg1) > len(seg2) else -1
        if seg1 != seg2:
            return 1 if seg1 > seg2 else -1

    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def _rpm_split(evr: str) -> tuple[int, str, str | None]:
    evr = evr.strip()
    epoch = 0
    if ":" in evr:
        e, evr = evr.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in evr:
        version, release = evr.rsplit("-", 1)
        return epoch, version, release
    return epoch, evr, None


def compare_rpm(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return _sign(ea - eb)
    c = rpmvercmp(va, vb)
    if c:
        return c
    if ra is None or rb is None:
        # A version without a release matches any release of that version.
        return 0
    return rpmvercmp(ra, rb)


# ---------------------------------------------------------------------- apk

_APK_SUFFIX_RANK = {
    "alpha": 0,
    "beta": 1,
    "pre": 2,
    "rc": 3,
    "": 4,  # no suffix
    "cvs": 5,
    "svn": 6,
    "git": 7,
    "hg": 8,
    "p": 9,
}
_APK_RE = re.compile(
    r"^(?P<nums>\d+(?:\.\d+)*)(?P<letter>[a-z]?)(?P<suffixes>(?:_[a-z]+\d*)*)"
    r"(?:~[0-9a-f]+)?(?:-r(?P<rev>\d+))?$"
)


def _apk_parse(v: str):
    m = _APK_RE.match(v.strip())
    if not m:
        return None
    nums = m.group("nums").split(".")
    suffixes = []
    for part in m.group("suffixes").split("_")[1:]:
        sm = re.match(r"([a-z]+)(\d*)", part)
        name, num = sm.group(1), sm.group(2)
        suffixes.append((_APK_SUFFIX_RANK.get(name, 4), int(num) if num else 0))
    return nums, m.group("letter"), suffixes, int(m.group("rev") or 0)


def compare_apk(a: str, b: str) -> int:
    pa, pb = _apk_parse(a), _apk_parse(b)
    if pa is None or pb is None:
        return compare_dpkg(a, b)
    nums_a, let_a, suf_a, rev_a = pa
    nums_b, let_b, suf_b, rev_b = pb
    for idx, (x, y) in enumerate(zip(nums_a, nums_b)):
        if idx > 0 and (x.startswith("0") or y.startswith("0")):
            # apk compares components with leading zeros like decimal fractions
            if x != y:
                return 1 if x > y else -1
            continue
        if int(x) != int(y):
            return 1 if int(x) > int(y) else -1
    if len(nums_a) != len(nums_b):
        return 1 if len(nums_a) > len(nums_b) else -1
    if let_a != let_b:
        return 1 if let_a > let_b else -1
    no_suffix = (_APK_SUFFIX_RANK[""], 0)
    for k in range(max(len(suf_a), len(suf_b))):
        x = suf_a[k] if k < len(suf_a) else no_suffix
        y = suf_b[k] if k < len(suf_b) else no_suffix
        if x != y:
            return 1 if x > y else -1
    return _sign(rev_a - rev_b)


# ------------------------------------------------------------------ dispatch

_COMPARATORS: dict[str, Callable[[str, str], int]] = {
    "ubuntu": compare_dpkg,
    "debian": compare_dpkg,
    "alpine": compare_apk,
    "rocky": compare_rpm,
    "almalinux": compare_rpm,
    "redhat": compare_rpm,
}


def comparator(family: str) -> Callable[[str, str], int]:
    return _COMPARATORS.get(family, compare_dpkg)


def compare(family: str, a: str, b: str) -> int:
    return comparator(family)(a, b)


def sort_key(family: str):
    return cmp_to_key(comparator(family))
