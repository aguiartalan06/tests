import json
from datetime import datetime

from netmon import report
from netmon.diff import diff_scans
from netmon.report import (
    format_ports,
    render_console,
    render_json,
    render_markdown,
    render_table,
    risky_port_notes,
    service_name,
    write_report,
)


def test_service_name_and_ports():
    assert service_name(22) == "ssh"
    assert service_name(62078) == "iphone-sync"
    assert format_ports([22, 443]) == "22 (ssh), 443 (https)"
    assert format_ports([]) == "-"
    assert format_ports([47123]).startswith("47123")


def test_render_table_truncates_and_aligns():
    text = render_table(["A", "B"], [["x" * 50, "y"], ["short", "zz"]], max_width=10)
    lines = text.splitlines()
    assert lines[0].startswith("A")
    assert "…" in lines[2]
    assert len(lines) == 4
    assert lines[3].startswith("short")


def test_console_baseline_run(baseline_scan):
    text = render_console(baseline_scan, None)
    assert "scan #1 of 192.168.1.0/24" in text
    assert "Devices (5)" in text
    assert "192.168.1.20" in text and "b8:27:eb:12:34:56" in text and "pi.local" in text
    assert "22 (ssh), 80 (http)" in text
    assert "Saved as BASELINE" in text
    assert "\033[" not in text  # colour off by default


def test_console_hides_baseline_notice_when_asked(baseline_scan):
    text = render_console(baseline_scan, None, show_baseline_notice=False)
    assert "Saved as BASELINE" not in text


def test_console_diff_run(baseline_scan, current_scan, tmp_path):
    diff = diff_scans(baseline_scan, current_scan)
    text = render_console(current_scan, diff, report_path=tmp_path / "r.md", color=True)
    assert "Changes vs baseline" in text
    assert "[+] NEW DEVICE" in text and "192.168.1.50" in text and "Amazon Technologies" in text
    assert "[-] MISSING" in text and "192.168.1.30" in text and "Sonos" in text
    assert "[!] NEW PORTS" in text and "5900 (vnc)" in text
    assert "[i] ip changed  192.168.1.40 -> 192.168.1.41" in text
    assert "2 device(s) unchanged" in text
    assert "Worth a look" in text and "VNC" in text
    assert "Report written to" in text and "r.md" in text
    assert "\033[31m" in text  # red used for new ports


def test_console_no_changes(baseline_scan, make_scan, baseline_devices):
    diff = diff_scans(baseline_scan, make_scan(list(baseline_devices), scan_id=2))
    text = render_console(baseline_scan, diff)
    assert "No changes." in text


def test_risky_port_notes(baseline_scan, current_scan):
    assert risky_port_notes(baseline_scan.devices) == []
    notes = risky_port_notes(current_scan.devices)
    assert len(notes) == 1 and notes[0].startswith("192.168.1.20 (pi.local) has 5900 (vnc) open")


def test_markdown_baseline(baseline_scan):
    md = render_markdown(baseline_scan, None)
    assert md.startswith("# Network scan report #1 - 2026-09-20 09:00:00")
    assert "| Subnet | 192.168.1.0/24 |" in md
    assert "| Compared against | none (this scan is the baseline) |" in md
    assert "saved as the **baseline**" in md
    assert "## All devices" in md
    assert "| 192.168.1.20 | b8:27:eb:12:34:56 | Raspberry Pi Foundation | pi.local | 22 (ssh), 80 (http) | ping |" in md
    assert "## Changes" not in md
    assert md.endswith("\n")


def test_markdown_with_changes(baseline_scan, current_scan):
    diff = diff_scans(baseline_scan, current_scan)
    md = render_markdown(current_scan, diff)
    assert "| Compared against | baseline from 2026-09-20 09:00:00 |" in md
    assert "- **1** new device(s)" in md
    assert "- **1** missing device(s)" in md
    assert "- **1** newly opened port(s)" in md
    assert "### New devices" in md and "| 192.168.1.50 | f0:d2:f1:44:55:66 | Amazon Technologies | echo.local | - |" in md
    assert "### Missing devices" in md and "| 192.168.1.30 | 5c:aa:fd:11:22:33 | Sonos | - | - |" in md
    assert "### Port changes" in md and "| 192.168.1.20 | pi.local | 5900 (vnc) | - |" in md
    assert "### Address / hostname changes" in md and "192.168.1.40 -> 192.168.1.41" in md
    assert "## Worth a look" in md
    assert "Ports probed: 22, 53, 80, 443, 5000, 5900, 7000, 62078" in md


def test_markdown_escapes_pipes(make_scan, make_device):
    scan = make_scan([make_device("10.0.0.1", "aa:bb:cc:dd:ee:ff", hostname="weird|name")], scan_id=3)
    md = render_markdown(scan, None)
    assert "weird\\|name" in md


def test_write_report_names_and_collisions(tmp_path):
    when = datetime(2026, 9, 26, 14, 3, 11)
    first = write_report("# one\n", tmp_path / "reports", when)
    second = write_report("# two\n", tmp_path / "reports", when)
    assert first.name == "2026-09-26_140311.md"
    assert second.name == "2026-09-26_140311_2.md"
    assert first.read_text() == "# one\n" and second.read_text() == "# two\n"


def test_render_json(baseline_scan, current_scan):
    diff = diff_scans(baseline_scan, current_scan)
    payload = json.loads(render_json(current_scan, diff))
    assert payload["scan"]["id"] == 2
    assert payload["scan"]["subnet"] == "192.168.1.0/24"
    assert payload["scan"]["devices"][0]["key"] == "a4:2b:8c:01:34:56"
    assert payload["diff"]["reference_id"] == 1
    assert [d["ip"] for d in payload["diff"]["new_devices"]] == ["192.168.1.50"]
    assert [d["ip"] for d in payload["diff"]["missing_devices"]] == ["192.168.1.30"]
    assert payload["diff"]["changed_devices"][0]["new_ports"] == [5900]
    assert payload["diff"]["has_alerts"] is True
    assert json.loads(render_json(baseline_scan, None))["diff"] is None


def test_color_enabled_respects_tty(monkeypatch):
    class Stream:
        def isatty(self):
            return True

    assert report.color_enabled(Stream()) is True

    class NoTTY:
        pass

    assert report.color_enabled(NoTTY()) is False
