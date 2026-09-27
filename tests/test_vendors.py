from pathlib import Path

import pytest

from netmon import vendors
from netmon.vendors import VendorLookup, is_locally_administered, normalize_mac, oui_prefix


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("A4:2B:8C:01:34:56", "a4:2b:8c:01:34:56"),
        ("a4:2b:8c:1:34:56", "a4:2b:8c:01:34:56"),  # macOS arp -a drops leading zeros
        ("0:1c:b3:9:2a:ff", "00:1c:b3:09:2a:ff"),
        ("A4-2B-8C-01-34-56", "a4:2b:8c:01:34:56"),
        ("a42b.8c01.3456", "a4:2b:8c:01:34:56"),
        ("a42b8c013456", "a4:2b:8c:01:34:56"),
        ("  a4:2b:8c:01:34:56\n", "a4:2b:8c:01:34:56"),
    ],
)
def test_normalize_mac_valid(raw, expected):
    assert normalize_mac(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "(incomplete)", "<incomplete>", "zz:zz:zz:zz:zz:zz", "a4:2b:8c", "a42b8c0134", "a4:2b:8c:01:34:56:78"])
def test_normalize_mac_invalid(raw):
    assert normalize_mac(raw) is None


def test_oui_prefix():
    assert oui_prefix("b8:27:eb:12:34:56") == "B827EB"
    assert oui_prefix("garbage") is None


@pytest.mark.parametrize(
    "mac,expected",
    [
        ("da:12:34:56:78:9a", True),   # 0xda -> bit 1 set
        ("02:42:0a:00:00:05", True),   # docker style
        ("b8:27:eb:12:34:56", False),
        ("a4:2b:8c:01:34:56", False),
        ("not-a-mac", False),
    ],
)
def test_is_locally_administered(mac, expected):
    assert is_locally_administered(mac) is expected


def test_bundled_lookup(vendors):
    assert len(vendors) > 500
    assert vendors.lookup("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"
    assert vendors.lookup("0:1c:b3:9:2a:ff") == "Apple"
    assert vendors.lookup("A4:2B:8C:01:34:56") == "Netgear"


def test_lookup_unknown_and_randomized(vendors):
    assert vendors.lookup(None) == "Unknown"
    assert vendors.lookup("00:11:22:33:44:55") == "Unknown"
    assert vendors.lookup("da:12:34:56:78:9a") == "Private (randomized MAC)"
    assert vendors.lookup("garbage") == "Unknown"


def test_user_ieee_csv_overrides_bundled(tmp_path: Path):
    csv_file = tmp_path / "oui.csv"
    csv_file.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,B827EB,"Raspberry Pi Foundation (from IEEE)",Cambridge GB\n'
        'MA-L,001122,"Custom Vendor Ltd",Somewhere\n',
        encoding="utf-8",
    )
    lookup = VendorLookup(user_file=csv_file)
    assert lookup.lookup("b8:27:eb:00:00:01") == "Raspberry Pi Foundation (from IEEE)"
    assert lookup.lookup("00:11:22:33:44:55") == "Custom Vendor Ltd"


def test_missing_files_are_tolerated(tmp_path: Path):
    lookup = VendorLookup(bundled_file=tmp_path / "nope.txt", user_file=tmp_path / "nope.csv", extra={"aabbcc": "Extra Co"})
    assert len(lookup) == 1
    assert lookup.lookup("aa:bb:cc:00:00:00") == "Extra Co"


def test_bundled_file_has_no_duplicates_or_bad_lines():
    lines = [l.strip() for l in vendors.BUNDLED_OUI_FILE.read_text().splitlines()]
    entries = [l for l in lines if l and not l.startswith("#")]
    prefixes = [l.split("\t")[0] for l in entries]
    assert all(len(p) == 6 and int(p, 16) >= 0 for p in prefixes)
    assert len(prefixes) == len(set(prefixes)), "duplicate OUI prefix in oui.txt"


def test_update_oui_database(tmp_path: Path, monkeypatch):
    payload = (
        b"Registry,Assignment,Organization Name,Organization Address\n"
        b'MA-L,ABCDEF,"Test Vendor",Nowhere\n'
    )

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return payload

    monkeypatch.setattr(vendors.urllib.request, "urlopen", lambda req, timeout=60: FakeResponse())
    dest = tmp_path / "sub" / "oui.csv"
    assert vendors.update_oui_database(dest) == 1
    assert dest.read_bytes() == payload
    assert VendorLookup(user_file=dest).lookup("ab:cd:ef:00:00:00") == "Test Vendor"


def test_update_oui_database_rejects_garbage(tmp_path: Path, monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"<html>not a csv</html>"

    monkeypatch.setattr(vendors.urllib.request, "urlopen", lambda req, timeout=60: FakeResponse())
    dest = tmp_path / "oui.csv"
    with pytest.raises(ValueError):
        vendors.update_oui_database(dest)
    assert not dest.exists()
