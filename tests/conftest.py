"""Shared fixtures: canned devices and scans that look like a real home network."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable, List, Optional

import pytest

from netmon.models import Device, ScanResult
from netmon.vendors import VendorLookup


@pytest.fixture
def vendors() -> VendorLookup:
    """Bundled OUI table only - never touch ~/.netmon during tests."""
    return VendorLookup(user_file=None)


@pytest.fixture
def make_device():
    def _make(
        ip: str,
        mac: Optional[str] = None,
        vendor: str = "Unknown",
        hostname: Optional[str] = None,
        ports: Iterable[int] = (),
        source: str = "ping",
    ) -> Device:
        return Device(ip=ip, mac=mac, vendor=vendor, hostname=hostname, open_ports=list(ports), source=source)

    return _make


@pytest.fixture
def make_scan():
    def _make(
        devices: List[Device],
        *,
        subnet: str = "192.168.1.0/24",
        start: Optional[datetime] = None,
        duration: float = 12.5,
        method: str = "ping",
        ports: Optional[List[int]] = None,
        scan_id: Optional[int] = None,
        is_baseline: bool = False,
    ) -> ScanResult:
        start = start or datetime(2026, 9, 20, 9, 0, 0)
        return ScanResult(
            subnet=subnet,
            started_at=start,
            finished_at=start + timedelta(seconds=duration),
            devices=devices,
            method=method,
            ports_scanned=ports if ports is not None else [22, 53, 80, 443, 5000, 5900, 7000, 62078],
            id=scan_id,
            is_baseline=is_baseline,
        )

    return _make


@pytest.fixture
def baseline_devices(make_device) -> List[Device]:
    return [
        make_device("192.168.1.1", "a4:2b:8c:01:34:56", "Netgear", "router.local", [53, 80, 443]),
        make_device("192.168.1.10", "3c:22:fb:aa:bb:cc", "Apple", "Talans-MacBook-Pro.local", [5000, 7000], source="self"),
        make_device("192.168.1.20", "b8:27:eb:12:34:56", "Raspberry Pi Foundation", "pi.local", [22, 80]),
        make_device("192.168.1.30", "5c:aa:fd:11:22:33", "Sonos", None, []),
        make_device("192.168.1.40", "da:12:34:56:78:9a", "Private (randomized MAC)", None, [62078], source="arp-cache"),
    ]


@pytest.fixture
def changed_devices(make_device) -> List[Device]:
    """Same network a week later: Sonos gone, a new Echo, VNC opened on the Pi, phone got a new IP."""
    return [
        make_device("192.168.1.1", "a4:2b:8c:01:34:56", "Netgear", "router.local", [53, 80, 443]),
        make_device("192.168.1.10", "3c:22:fb:aa:bb:cc", "Apple", "Talans-MacBook-Pro.local", [5000, 7000], source="self"),
        make_device("192.168.1.20", "b8:27:eb:12:34:56", "Raspberry Pi Foundation", "pi.local", [22, 80, 5900]),
        make_device("192.168.1.41", "da:12:34:56:78:9a", "Private (randomized MAC)", None, [62078], source="arp-cache"),
        make_device("192.168.1.50", "f0:d2:f1:44:55:66", "Amazon Technologies", "echo.local", []),
    ]


@pytest.fixture
def baseline_scan(make_scan, baseline_devices) -> ScanResult:
    return make_scan(baseline_devices, scan_id=1, is_baseline=True)


@pytest.fixture
def current_scan(make_scan, changed_devices) -> ScanResult:
    return make_scan(changed_devices, start=datetime(2026, 9, 27, 9, 0, 0), scan_id=2)
