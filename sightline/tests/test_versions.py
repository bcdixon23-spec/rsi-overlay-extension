import shutil
import subprocess

import pytest

from sightline.vulndb.versions import compare_apk, compare_dpkg, compare_rpm, rpmvercmp

DPKG_CASES = [
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0-2", -1),
    ("1:1.0", "2.0", 1),
    ("1.0~rc1", "1.0", -1),
    ("1.0", "1.0+b1", -1),
    ("1.0a", "1.0", 1),
    ("1.0.0", "1.0", 1),
    ("1.00", "1.0", 0),
    ("2.0~~", "2.0~", -1),
    ("1.2.3-1ubuntu0.2", "1.2.3-1ubuntu0.10", -1),
    ("3.0.13-0ubuntu3.10", "3.0.13-0ubuntu3.2", 1),
    ("8.9p1-3ubuntu0.6", "8.9p1-3ubuntu0.10", -1),
    ("1.0-1~deb12u1", "1.0-1", -1),
    ("1.0-1+deb12u1", "1.0-1", 1),
    ("0:1.0", "1.0", 0),
    ("1.0-0", "1.0", 0),
]


@pytest.mark.parametrize("a,b,expected", DPKG_CASES)
def test_dpkg(a, b, expected):
    assert compare_dpkg(a, b) == expected
    assert compare_dpkg(b, a) == -expected


@pytest.mark.skipif(not shutil.which("dpkg"), reason="dpkg not installed")
@pytest.mark.parametrize("a,b,_", DPKG_CASES)
def test_dpkg_matches_real_dpkg(a, b, _):
    def real(op):
        return subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode == 0

    expected = 0 if real("eq") else (1 if real("gt") else -1)
    assert compare_dpkg(a, b) == expected


# Vectors from rpm's own test suite (rpmvercmp.at)
RPMVERCMP_CASES = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1), ("2.0.1", "2.0.1", 0),
    ("2.0", "2.0.1", -1), ("2.0.1a", "2.0.1a", 0), ("2.0.1a", "2.0.1", 1), ("5.5p1", "5.5p1", 0),
    ("5.5p1", "5.5p2", -1), ("5.5p10", "5.5p1", 1), ("10xyz", "10.1xyz", -1),
    ("xyz10", "xyz10.1", -1), ("xyz.4", "xyz.4", 0), ("xyz.4", "8", -1), ("8", "xyz.4", 1),
    ("5.5p1", "5.5.p1", 0), ("5.5p1", "5.5.p10", -1), ("10b2", "10a1", 1), ("10a2", "10b2", -1),
    ("1.0aa", "1.0aa", 0), ("1.0a", "1.0aa", -1), ("10.0001", "10.1", 0), ("10.0001", "10.0039", -1),
    ("4.999.9", "5.0", -1), ("20101121", "20101122", -1), ("2_0", "2_0", 0), ("2.0", "2_0", 0),
    ("a", "a", 0), ("a+", "a_", 0), ("+", "_", 0), ("1.0~rc1", "1.0~rc1", 0),
    ("1.0~rc1", "1.0", -1), ("1.0", "1.0~rc1", 1), ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~rc1~git123", "1.0~rc1", -1), ("1.0^", "1.0^", 0), ("1.0^", "1.0", 1),
    ("1.0", "1.0^", -1), ("1.0^git1", "1.0^git2", -1), ("1.0^git1", "1.01", -1),
    ("1.0^20160101", "1.0.1", -1), ("1.0~rc1^git1", "1.0~rc1", 1), ("1.0^git1~pre", "1.0^git1", -1),
]  # fmt: skip


@pytest.mark.parametrize("a,b,expected", RPMVERCMP_CASES)
def test_rpmvercmp(a, b, expected):
    assert rpmvercmp(a, b) == expected


def test_rpm_evr():
    assert compare_rpm("1:3.0.7-24.el9", "0:3.0.7-25.el9") == 1  # epoch wins
    assert compare_rpm("0:3.0.7-24.el9", "0:3.0.7-25.el9_3") == -1
    assert compare_rpm("3.0.7", "3.0.7-25.el9") == 0  # no release matches any release
    assert compare_rpm("0:5.14.0-362.8.1.el9_3", "0:5.14.0-362.13.1.el9_3") == -1


APK_CASES = [
    ("1.2.3-r0", "1.2.3-r1", -1),
    ("1.2.3-r10", "1.2.3-r9", 1),
    ("1.2.3", "1.2.3-r0", 0),
    ("1.2.3_rc1-r0", "1.2.3-r0", -1),
    ("1.2.3_p1-r0", "1.2.3-r0", 1),
    ("1.2.3_alpha", "1.2.3_beta", -1),
    ("1.2.3a-r0", "1.2.3-r0", 1),
    ("1.2.10-r0", "1.2.9-r0", 1),
    ("1.2-r0", "1.2.1-r0", -1),
    ("3.1.4-r5", "3.1.4-r5", 0),
    ("1.36.1-r15", "1.36.1-r29", -1),
]


@pytest.mark.parametrize("a,b,expected", APK_CASES)
def test_apk(a, b, expected):
    assert compare_apk(a, b) == expected
    assert compare_apk(b, a) == -expected
