"""Compare two scans and describe what changed.

Pure functions only - nothing here touches the network or the database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from netmon.models import Device, ScanResult


@dataclass
class DeviceChange:
    """A device present in both scans whose details differ."""

    current: Device
    previous: Device
    new_ports: List[int] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)

    @property
    def ip_changed(self) -> bool:
        return self.current.ip != self.previous.ip

    @property
    def hostname_changed(self) -> bool:
        return bool(self.current.hostname and self.previous.hostname
                    and self.current.hostname != self.previous.hostname)

    @property
    def is_alert(self) -> bool:
        """Newly opened ports are security-relevant; the rest is informational."""
        return bool(self.new_ports)


@dataclass
class ScanDiff:
    reference: ScanResult
    current: ScanResult
    new_devices: List[Device] = field(default_factory=list)
    missing_devices: List[Device] = field(default_factory=list)
    changed_devices: List[DeviceChange] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def reference_label(self) -> str:
        return "baseline" if self.reference.is_baseline else f"scan #{self.reference.id}"

    @property
    def new_port_count(self) -> int:
        return sum(len(change.new_ports) for change in self.changed_devices)

    @property
    def has_alerts(self) -> bool:
        """True when something security-relevant happened."""
        return bool(self.new_devices or self.missing_devices or self.new_port_count)

    @property
    def has_changes(self) -> bool:
        return self.has_alerts or bool(self.changed_devices)


def diff_scans(reference: ScanResult, current: ScanResult) -> ScanDiff:
    """Match devices across the two scans by ``Device.key`` and classify them."""
    previous_by_key = {device.key: device for device in reference.devices}
    current_by_key = {device.key: device for device in current.devices}

    result = ScanDiff(reference=reference, current=current)

    for key, device in current_by_key.items():
        previous = previous_by_key.get(key)
        if previous is None:
            result.new_devices.append(device)
            continue
        new_ports = sorted(set(device.open_ports) - set(previous.open_ports))
        closed_ports = sorted(set(previous.open_ports) - set(device.open_ports))
        change = DeviceChange(current=device, previous=previous, new_ports=new_ports, closed_ports=closed_ports)
        if new_ports or closed_ports or change.ip_changed or change.hostname_changed:
            result.changed_devices.append(change)
        else:
            result.unchanged_count += 1

    for key, device in previous_by_key.items():
        if key not in current_by_key:
            result.missing_devices.append(device)

    result.new_devices.sort(key=lambda d: _ip_sort_key(d.ip))
    result.missing_devices.sort(key=lambda d: _ip_sort_key(d.ip))
    result.changed_devices.sort(key=lambda c: _ip_sort_key(c.current.ip))
    return result


def _ip_sort_key(ip: Optional[str]):
    try:
        return tuple(int(part) for part in (ip or "0.0.0.0").split("."))
    except ValueError:
        return (999, 999, 999, 999)
