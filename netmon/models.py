"""Plain data structures shared by the scanner, storage, diff and report layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Device:
    """One host seen on the network during a scan."""

    ip: str
    mac: Optional[str] = None
    vendor: str = "Unknown"
    hostname: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    # How the host was found: "arp", "ping", "arp-cache" or "self".
    source: str = ""

    @property
    def key(self) -> str:
        """Stable identity used to match devices across scans.

        MAC addresses survive DHCP lease changes, so they are preferred. A host
        with no known MAC falls back to its IP address.
        """
        if self.mac:
            return self.mac.lower()
        return f"ip:{self.ip}"

    @property
    def display_name(self) -> str:
        return self.hostname or self.vendor or self.ip


@dataclass
class ScanResult:
    """Everything we learned during one run of the monitor."""

    subnet: str
    started_at: datetime
    finished_at: datetime
    devices: List[Device]
    method: str = "ping"
    ports_scanned: List[int] = field(default_factory=list)
    id: Optional[int] = None
    is_baseline: bool = False

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def device_by_key(self, key: str) -> Optional[Device]:
        for device in self.devices:
            if device.key == key:
                return device
        return None
