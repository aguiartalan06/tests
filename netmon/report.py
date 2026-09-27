"""Human-readable output: console text, a Markdown report and a JSON dump."""

from __future__ import annotations

import json
import socket
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from netmon.diff import ScanDiff
from netmon.models import Device, ScanResult

SERVICE_NAMES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
    515: "printer", 548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 993: "imaps",
    995: "pop3s", 1883: "mqtt", 1900: "upnp", 2323: "telnet-alt", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 5000: "upnp/airplay", 5222: "xmpp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 7000: "airplay", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8123: "home-assistant", 8443: "https-alt",
    8883: "mqtts", 9000: "http-alt", 9100: "jetdirect", 27017: "mongodb", 32400: "plex",
    49152: "upnp", 62078: "iphone-sync",
}

# Ports that deserve a second look on a home network, with a one-line reason.
RISKY_PORTS: Dict[int, str] = {
    21: "FTP sends credentials in clear text",
    23: "Telnet is unencrypted and a classic IoT botnet entry point",
    2323: "Telnet on an alternate port is a common IoT default",
    445: "SMB file sharing - make sure it is intended and patched",
    3389: "Remote Desktop exposed on the LAN",
    5900: "VNC remote control - check it needs a password",
    6379: "Redis is unauthenticated by default",
    27017: "MongoDB is unauthenticated by default",
    3306: "MySQL listening on the network",
    5432: "PostgreSQL listening on the network",
    1883: "MQTT broker - check it requires authentication",
    7547: "TR-069 (CWMP) remote management on a router",
}


def service_name(port: int) -> str:
    name = SERVICE_NAMES.get(port)
    if name:
        return name
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, OverflowError):
        return ""


def format_port(port: int) -> str:
    name = service_name(port)
    return f"{port} ({name})" if name else str(port)


def format_ports(ports: Iterable[int]) -> str:
    ports = list(ports)
    return ", ".join(format_port(p) for p in ports) if ports else "-"


def format_dt(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #


class Palette:
    """ANSI colours, or no-ops when colour is disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)


def color_enabled(stream=None) -> bool:
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]], max_width: int = 28) -> str:
    """Fixed-width text table. Cells wider than ``max_width`` are truncated."""
    cells = [[_truncate(str(c), max_width) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers).rstrip(), fmt.format(*["-" * w for w in widths]).rstrip()]
    lines.extend(fmt.format(*row).rstrip() for row in cells)
    return "\n".join(lines)


def _device_rows(devices: Iterable[Device]) -> List[List[str]]:
    return [
        [d.ip, d.mac or "-", d.vendor or "Unknown", d.hostname or "-", format_ports(d.open_ports)]
        for d in devices
    ]


def render_console(
    result: ScanResult,
    diff: Optional[ScanDiff],
    report_path: Optional[Path] = None,
    color: bool = False,
    show_baseline_notice: bool = True,
) -> str:
    p = Palette(color)
    out: List[str] = []
    scan_label = f"scan #{result.id}" if result.id is not None else "scan"
    out.append(p.bold(f"Home Network Monitor - {scan_label} of {result.subnet}"))
    out.append(
        p.dim(
            f"{format_dt(result.started_at)} -> {result.finished_at.strftime('%H:%M:%S')}"
            f" ({result.duration_seconds:.1f}s) | discovery: {result.method}"
            f" | {len(result.ports_scanned)} ports probed per host"
        )
    )
    out.append("")
    out.append(p.bold(f"Devices ({len(result.devices)})"))
    out.append(render_table(["IP", "MAC", "Vendor", "Hostname", "Open ports"], _device_rows(result.devices), max_width=40))
    out.append("")

    if show_baseline_notice and result.is_baseline and diff is None:
        out.append(p.green("Saved as BASELINE. Future scans will be compared against this one."))
    elif diff is not None:
        ref = diff.reference
        out.append(p.bold(f"Changes vs {diff.reference_label} ({format_dt(ref.started_at)})"))
        if not diff.has_changes:
            out.append(p.green("  No changes."))
        for device in diff.new_devices:
            out.append(p.yellow(f"  [+] NEW DEVICE  {_device_line(device)}"))
        for device in diff.missing_devices:
            out.append(p.yellow(f"  [-] MISSING     {_device_line(device)}"))
        for change in diff.changed_devices:
            who = f"{change.current.ip}  {change.current.display_name}"
            if change.new_ports:
                out.append(p.red(f"  [!] NEW PORTS   {who}: {format_ports(change.new_ports)}"))
            if change.closed_ports:
                out.append(p.dim(f"  [i] closed      {who}: {format_ports(change.closed_ports)}"))
            if change.ip_changed:
                out.append(p.dim(f"  [i] ip changed  {change.previous.ip} -> {change.current.ip}  {change.current.display_name}"))
            if change.hostname_changed:
                out.append(p.dim(f"  [i] hostname    {change.previous.hostname} -> {change.current.hostname}  ({change.current.ip})"))
        out.append(p.dim(f"  {diff.unchanged_count} device(s) unchanged."))

    notes = risky_port_notes(result.devices)
    if notes:
        out.append("")
        out.append(p.bold("Worth a look"))
        for note in notes:
            out.append(p.yellow(f"  * {note}"))

    if report_path is not None:
        out.append("")
        out.append(p.dim(f"Report written to {report_path}"))
    return "\n".join(out)


def _device_line(device: Device) -> str:
    parts = [device.ip, device.mac or "-", device.vendor or "Unknown"]
    if device.hostname:
        parts.append(device.hostname)
    if device.open_ports:
        parts.append(f"ports: {format_ports(device.open_ports)}")
    return "  ".join(parts)


def risky_port_notes(devices: Iterable[Device]) -> List[str]:
    notes: List[str] = []
    for device in devices:
        for port in device.open_ports:
            reason = RISKY_PORTS.get(port)
            if reason:
                notes.append(f"{device.ip} ({device.display_name}) has {format_port(port)} open: {reason}")
    return notes


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def _md_escape(text: Optional[str]) -> str:
    return (text or "-").replace("|", "\\|")


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_md_escape(c) for c in row) + " |")
    return "\n".join(lines)


def render_markdown(result: ScanResult, diff: Optional[ScanDiff]) -> str:
    scan_label = f"#{result.id}" if result.id is not None else ""
    out: List[str] = [f"# Network scan report {scan_label} - {format_dt(result.started_at)}", ""]

    compared = "-"
    if result.is_baseline and diff is None:
        compared = "none (this scan is the baseline)"
    elif diff is not None:
        compared = f"{diff.reference_label} from {format_dt(diff.reference.started_at)}"

    out.append(_md_table(
        ["Field", "Value"],
        [
            ["Subnet", result.subnet],
            ["Discovery method", result.method],
            ["Started", format_dt(result.started_at)],
            ["Finished", format_dt(result.finished_at)],
            ["Duration", f"{result.duration_seconds:.1f}s"],
            ["Devices found", str(len(result.devices))],
            ["Ports probed per host", str(len(result.ports_scanned))],
            ["Compared against", compared],
        ],
    ))
    out.append("")

    out.append("## Summary")
    out.append("")
    if result.is_baseline and diff is None:
        out.append("This scan was saved as the **baseline**. Future runs are compared against it.")
    elif diff is None:
        out.append("No reference scan available for comparison.")
    elif not diff.has_changes:
        out.append(f"No changes compared to the {diff.reference_label}.")
    else:
        out.append(f"- **{len(diff.new_devices)}** new device(s)")
        out.append(f"- **{len(diff.missing_devices)}** missing device(s)")
        out.append(f"- **{diff.new_port_count}** newly opened port(s)")
        out.append(f"- {diff.unchanged_count} device(s) unchanged")
    out.append("")

    if diff is not None and diff.has_changes:
        out.append(f"## Changes vs {diff.reference_label}")
        out.append("")
        if diff.new_devices:
            out.append("### New devices")
            out.append("")
            out.append(_md_table(["IP", "MAC", "Vendor", "Hostname", "Open ports"], _device_rows(diff.new_devices)))
            out.append("")
        if diff.missing_devices:
            out.append("### Missing devices")
            out.append("")
            out.append(_md_table(["IP", "MAC", "Vendor", "Hostname", "Ports (last seen)"], _device_rows(diff.missing_devices)))
            out.append("")
        port_changes = [c for c in diff.changed_devices if c.new_ports or c.closed_ports]
        if port_changes:
            out.append("### Port changes")
            out.append("")
            out.append(_md_table(
                ["IP", "Device", "Newly opened", "Closed"],
                [
                    [c.current.ip, c.current.display_name, format_ports(c.new_ports), format_ports(c.closed_ports)]
                    for c in port_changes
                ],
            ))
            out.append("")
        other = [c for c in diff.changed_devices if c.ip_changed or c.hostname_changed]
        if other:
            out.append("### Address / hostname changes")
            out.append("")
            rows = []
            for c in other:
                rows.append([
                    c.current.mac or c.current.key,
                    f"{c.previous.ip} -> {c.current.ip}" if c.ip_changed else c.current.ip,
                    f"{c.previous.hostname} -> {c.current.hostname}" if c.hostname_changed else (c.current.hostname or "-"),
                ])
            out.append(_md_table(["Device (MAC)", "IP", "Hostname"], rows))
            out.append("")

    out.append("## All devices")
    out.append("")
    rows = [
        [d.ip, d.mac or "-", d.vendor or "Unknown", d.hostname or "-", format_ports(d.open_ports), d.source or "-"]
        for d in result.devices
    ]
    out.append(_md_table(["IP", "MAC", "Vendor", "Hostname", "Open ports", "Seen via"], rows))
    out.append("")

    notes = risky_port_notes(result.devices)
    if notes:
        out.append("## Worth a look")
        out.append("")
        out.extend(f"- {note}" for note in notes)
        out.append("")

    out.append(f"Ports probed: {', '.join(str(p) for p in result.ports_scanned) or '-'}")
    out.append("")
    return "\n".join(out)


def write_report(markdown: str, reports_dir: Path, started_at: datetime) -> Path:
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    stem = started_at.strftime("%Y-%m-%d_%H%M%S")
    path = reports_dir / f"{stem}.md"
    counter = 1
    while path.exists():
        counter += 1
        path = reports_dir / f"{stem}_{counter}.md"
    path.write_text(markdown, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def _device_dict(device: Device) -> dict:
    data = asdict(device)
    data["key"] = device.key
    return data


def render_json(result: ScanResult, diff: Optional[ScanDiff]) -> str:
    payload = {
        "scan": {
            "id": result.id,
            "subnet": result.subnet,
            "method": result.method,
            "started_at": result.started_at.isoformat(timespec="seconds"),
            "finished_at": result.finished_at.isoformat(timespec="seconds"),
            "is_baseline": result.is_baseline,
            "ports_scanned": result.ports_scanned,
            "devices": [_device_dict(d) for d in result.devices],
        },
        "diff": None,
    }
    if diff is not None:
        payload["diff"] = {
            "reference_id": diff.reference.id,
            "reference_label": diff.reference_label,
            "new_devices": [_device_dict(d) for d in diff.new_devices],
            "missing_devices": [_device_dict(d) for d in diff.missing_devices],
            "changed_devices": [
                {
                    "key": c.current.key,
                    "ip": c.current.ip,
                    "previous_ip": c.previous.ip,
                    "new_ports": c.new_ports,
                    "closed_ports": c.closed_ports,
                }
                for c in diff.changed_devices
            ],
            "unchanged_count": diff.unchanged_count,
            "has_alerts": diff.has_alerts,
        }
    return json.dumps(payload, indent=2)
