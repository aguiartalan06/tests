"""SQLite persistence for scan results.

Schema (three tables):

    scans       one row per run; ``is_baseline`` marks the reference scan
    devices     one row per device per scan, keyed by MAC (or ip:<addr>)
    open_ports  one row per open TCP port per device row

The first scan ever saved automatically becomes the baseline. Later scans are
compared against it (or against the previous scan) by the diff module.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from netmon.models import Device, ScanResult

DEFAULT_DB_PATH = Path("netmon.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT    NOT NULL,
    finished_at   TEXT    NOT NULL,
    subnet        TEXT    NOT NULL,
    method        TEXT    NOT NULL,
    ports_scanned TEXT    NOT NULL,
    is_baseline   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    key      TEXT    NOT NULL,
    ip       TEXT    NOT NULL,
    mac      TEXT,
    vendor   TEXT,
    hostname TEXT,
    source   TEXT
);

CREATE TABLE IF NOT EXISTS open_ports (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port      INTEGER NOT NULL,
    PRIMARY KEY (device_id, port)
);

CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_devices_key  ON devices(key);
CREATE INDEX IF NOT EXISTS idx_scans_baseline ON scans(is_baseline);
"""


class Storage:
    """Thin wrapper around a SQLite database. Use as a context manager."""

    def __init__(self, path: Union[str, Path] = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)

    # -- lifecycle --------------------------------------------------------- #

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- writes ------------------------------------------------------------ #

    def save_scan(self, result: ScanResult, as_baseline: Optional[bool] = None) -> int:
        """Persist a scan. Returns its id and sets ``result.id``/``is_baseline``.

        ``as_baseline=None`` (default) makes the scan the baseline only when no
        baseline exists yet - i.e. on the very first run.
        """
        if as_baseline is None:
            as_baseline = self.get_baseline_id() is None

        with self._conn:
            if as_baseline:
                self._conn.execute("UPDATE scans SET is_baseline = 0")
            cursor = self._conn.execute(
                "INSERT INTO scans (started_at, finished_at, subnet, method, ports_scanned, is_baseline)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    result.started_at.isoformat(timespec="seconds"),
                    result.finished_at.isoformat(timespec="seconds"),
                    result.subnet,
                    result.method,
                    json.dumps(result.ports_scanned),
                    1 if as_baseline else 0,
                ),
            )
            scan_id = int(cursor.lastrowid)
            for device in result.devices:
                dev_cursor = self._conn.execute(
                    "INSERT INTO devices (scan_id, key, ip, mac, vendor, hostname, source)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, device.key, device.ip, device.mac, device.vendor, device.hostname, device.source),
                )
                device_id = dev_cursor.lastrowid
                self._conn.executemany(
                    "INSERT OR IGNORE INTO open_ports (device_id, port) VALUES (?, ?)",
                    [(device_id, int(port)) for port in device.open_ports],
                )

        result.id = scan_id
        result.is_baseline = bool(as_baseline)
        return scan_id

    def set_baseline(self, scan_id: int) -> None:
        """Promote an existing scan to be the baseline."""
        with self._conn:
            row = self._conn.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                raise KeyError(f"No scan with id {scan_id}")
            self._conn.execute("UPDATE scans SET is_baseline = 0")
            self._conn.execute("UPDATE scans SET is_baseline = 1 WHERE id = ?", (scan_id,))

    def clear_baseline(self) -> None:
        """Forget the baseline; the next saved scan becomes the new one."""
        with self._conn:
            self._conn.execute("UPDATE scans SET is_baseline = 0")

    def delete_scan(self, scan_id: int) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    # -- reads ------------------------------------------------------------- #

    def get_baseline_id(self) -> Optional[int]:
        row = self._conn.execute("SELECT id FROM scans WHERE is_baseline = 1 ORDER BY id DESC LIMIT 1").fetchone()
        return int(row["id"]) if row else None

    def get_baseline(self) -> Optional[ScanResult]:
        scan_id = self.get_baseline_id()
        return self.get_scan(scan_id) if scan_id is not None else None

    def get_latest(self, exclude_id: Optional[int] = None) -> Optional[ScanResult]:
        if exclude_id is None:
            row = self._conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        else:
            row = self._conn.execute(
                "SELECT id FROM scans WHERE id != ? ORDER BY id DESC LIMIT 1", (exclude_id,)
            ).fetchone()
        return self.get_scan(int(row["id"])) if row else None

    def get_scan(self, scan_id: int) -> Optional[ScanResult]:
        row = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        devices = self._load_devices(scan_id)
        return ScanResult(
            id=int(row["id"]),
            subnet=row["subnet"],
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=datetime.fromisoformat(row["finished_at"]),
            devices=devices,
            method=row["method"],
            ports_scanned=json.loads(row["ports_scanned"] or "[]"),
            is_baseline=bool(row["is_baseline"]),
        )

    def list_scans(self, limit: int = 20) -> List[dict]:
        rows = self._conn.execute(
            "SELECT s.id, s.started_at, s.finished_at, s.subnet, s.method, s.is_baseline,"
            "       (SELECT COUNT(*) FROM devices d WHERE d.scan_id = s.id) AS device_count"
            "  FROM scans s ORDER BY s.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def count_scans(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])

    def _load_devices(self, scan_id: int) -> List[Device]:
        rows = self._conn.execute(
            "SELECT * FROM devices WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        devices: List[Device] = []
        for row in rows:
            ports = [
                int(p["port"])
                for p in self._conn.execute(
                    "SELECT port FROM open_ports WHERE device_id = ? ORDER BY port", (row["id"],)
                ).fetchall()
            ]
            devices.append(
                Device(
                    ip=row["ip"],
                    mac=row["mac"],
                    vendor=row["vendor"] or "Unknown",
                    hostname=row["hostname"],
                    open_ports=ports,
                    source=row["source"] or "",
                )
            )
        return devices
