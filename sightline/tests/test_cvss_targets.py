import pytest

from sightline.models import severity_from_score
from sightline.targets import TargetError, expand_targets, is_public
from sightline.vulndb.cvss import score


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
        ("AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None),
        ("garbage", None),
    ],
)
def test_cvss(vector, expected):
    assert score(vector) == expected


def test_severity_from_score():
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(5.9) == "medium"
    assert severity_from_score(0.1) == "low"
    assert severity_from_score(None) == "unknown"


def test_targets_cidr_and_ranges():
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert expand_targets("10.0.0.5-7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    assert expand_targets("10.0.0.254-10.0.1.1") == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]
    assert expand_targets(["a.example, b-1.example", "a.example"]) == ["a.example", "b-1.example"]
    assert expand_targets("192.168.1.9/32") == ["192.168.1.9"]


def test_targets_file(tmp_path):
    f = tmp_path / "hosts.txt"
    f.write_text("# office\n10.1.1.1\n10.1.1.2  # printer\n\nweb01\n")
    assert expand_targets(f"@{f}") == ["10.1.1.1", "10.1.1.2", "web01"]


def test_targets_errors():
    with pytest.raises(TargetError):
        expand_targets("10.0.0.0/8", max_hosts=1000)
    with pytest.raises(TargetError):
        expand_targets("10.0.0.9-3")
    with pytest.raises(TargetError):
        expand_targets("")


def test_is_public():
    assert is_public("8.8.8.8")
    assert not is_public("192.168.1.1")
    assert not is_public("127.0.0.1")
    assert not is_public("not-an-ip")
