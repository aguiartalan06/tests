from datetime import datetime

import pytest

from netmon.storage import Storage


@pytest.fixture
def storage(tmp_path):
    with Storage(tmp_path / "data" / "netmon.db") as store:
        yield store


def test_first_scan_becomes_baseline(storage, baseline_scan, current_scan):
    first_id = storage.save_scan(baseline_scan)
    assert first_id == 1
    assert baseline_scan.is_baseline is True
    assert storage.get_baseline_id() == 1

    second_id = storage.save_scan(current_scan)
    assert second_id == 2
    assert current_scan.is_baseline is False
    assert storage.get_baseline_id() == 1
    assert storage.count_scans() == 2


def test_round_trip_preserves_devices_and_ports(storage, baseline_scan):
    scan_id = storage.save_scan(baseline_scan)
    loaded = storage.get_scan(scan_id)
    assert loaded is not None
    assert loaded.id == scan_id
    assert loaded.subnet == "192.168.1.0/24"
    assert loaded.method == "ping"
    assert loaded.is_baseline is True
    assert loaded.started_at == datetime(2026, 9, 20, 9, 0, 0)
    assert loaded.ports_scanned == baseline_scan.ports_scanned
    assert [d.ip for d in loaded.devices] == [d.ip for d in baseline_scan.devices]
    for original, restored in zip(baseline_scan.devices, loaded.devices):
        assert restored.mac == original.mac
        assert restored.vendor == original.vendor
        assert restored.hostname == original.hostname
        assert restored.open_ports == original.open_ports
        assert restored.source == original.source
        assert restored.key == original.key


def test_get_latest_and_exclude(storage, baseline_scan, current_scan):
    storage.save_scan(baseline_scan)
    storage.save_scan(current_scan)
    assert storage.get_latest().id == 2
    assert storage.get_latest(exclude_id=2).id == 1
    assert storage.get_latest(exclude_id=1).id == 2


def test_set_and_clear_baseline(storage, baseline_scan, current_scan, make_scan):
    storage.save_scan(baseline_scan)
    storage.save_scan(current_scan)
    storage.set_baseline(2)
    assert storage.get_baseline_id() == 2
    assert storage.get_scan(1).is_baseline is False

    storage.clear_baseline()
    assert storage.get_baseline() is None
    third = make_scan([], scan_id=None)
    storage.save_scan(third)
    assert third.is_baseline is True
    assert storage.get_baseline_id() == 3


def test_explicit_as_baseline_replaces_previous(storage, baseline_scan, current_scan):
    storage.save_scan(baseline_scan)
    storage.save_scan(current_scan, as_baseline=True)
    assert storage.get_baseline_id() == 2
    assert storage.get_scan(1).is_baseline is False


def test_set_baseline_unknown_id(storage):
    with pytest.raises(KeyError):
        storage.set_baseline(42)


def test_missing_scan_returns_none(storage):
    assert storage.get_scan(99) is None
    assert storage.get_baseline() is None
    assert storage.get_latest() is None


def test_list_scans(storage, baseline_scan, current_scan):
    storage.save_scan(baseline_scan)
    storage.save_scan(current_scan)
    scans = storage.list_scans()
    assert [s["id"] for s in scans] == [2, 1]
    assert scans[1]["is_baseline"] == 1
    assert scans[0]["device_count"] == 5
    assert scans[0]["started_at"].startswith("2026-09-27")


def test_delete_scan_cascades(storage, baseline_scan):
    scan_id = storage.save_scan(baseline_scan)
    storage.delete_scan(scan_id)
    assert storage.get_scan(scan_id) is None
    assert storage._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
    assert storage._conn.execute("SELECT COUNT(*) FROM open_ports").fetchone()[0] == 0


def test_database_persists_across_connections(tmp_path, baseline_scan):
    path = tmp_path / "persist.db"
    with Storage(path) as store:
        store.save_scan(baseline_scan)
    with Storage(path) as store:
        assert store.count_scans() == 1
        assert store.get_baseline().devices[0].ip == "192.168.1.1"


def test_device_without_mac_is_keyed_by_ip(storage, make_scan, make_device):
    scan = make_scan([make_device("192.168.1.77", None, ports=[80])])
    storage.save_scan(scan)
    loaded = storage.get_scan(1)
    assert loaded.devices[0].key == "ip:192.168.1.77"
    assert loaded.devices[0].mac is None
