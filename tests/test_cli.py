"""End-to-end CLI tests with the network layer replaced by canned scan data."""

import ipaddress
import json
from datetime import datetime, timedelta

import pytest

from netmon import cli
from netmon.netinfo import LocalNetwork, NetworkDetectionError
from netmon.models import ScanResult
from netmon.scanner import COMMON_PORTS, DiscoveryError

LOCAL = LocalNetwork("en0", "192.168.1.10", ipaddress.IPv4Network("192.168.1.0/24"), "3c:22:fb:aa:bb:cc")


@pytest.fixture
def fake_network(monkeypatch, baseline_devices, changed_devices):
    """Replace detection + scanning. Each call to run_scan returns the next canned device list."""
    queue = [list(baseline_devices), list(changed_devices), list(changed_devices)]
    calls = []
    clock = [datetime(2026, 9, 26, 14, 3, 11)]

    def fake_detect(interface=None):
        return LOCAL

    def fake_run_scan(local, ports, method="auto", **kwargs):
        calls.append({"local": local, "ports": ports, "method": method, **kwargs})
        devices = queue.pop(0)
        started = clock[0]
        clock[0] = started + timedelta(days=1)
        return ScanResult(
            subnet=local.cidr,
            started_at=started,
            finished_at=started + timedelta(seconds=9),
            devices=devices,
            method="ping",
            ports_scanned=list(ports),
        )

    monkeypatch.setattr(cli, "detect_network", fake_detect)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    return calls


def _args(tmp_path, *extra):
    return ["scan", "--db", str(tmp_path / "netmon.db"), "--reports-dir", str(tmp_path / "reports"), "-q", *extra]


def test_first_run_creates_baseline_and_report(tmp_path, capsys, fake_network):
    assert cli.main(_args(tmp_path)) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "Saved as BASELINE" in out
    assert "Devices (5)" in out
    reports = sorted((tmp_path / "reports").glob("*.md"))
    assert [r.name for r in reports] == ["2026-09-26_140311.md"]
    assert "saved as the **baseline**" in reports[0].read_text()
    assert fake_network[0]["ports"] == COMMON_PORTS
    assert fake_network[0]["method"] == "auto"
    assert fake_network[0]["resolve_names"] is True


def test_second_run_reports_changes_and_exit_code(tmp_path, capsys, fake_network):
    cli.main(_args(tmp_path))
    capsys.readouterr()
    code = cli.main(_args(tmp_path, "--fail-on-change", "--no-color"))
    out = capsys.readouterr().out
    assert code == cli.EXIT_CHANGES
    assert "Changes vs baseline" in out
    assert "[+] NEW DEVICE  192.168.1.50" in out
    assert "[-] MISSING     192.168.1.30" in out
    assert "[!] NEW PORTS   192.168.1.20  pi.local: 5900 (vnc)" in out
    reports = sorted((tmp_path / "reports").glob("*.md"))
    assert len(reports) == 2
    assert "### New devices" in reports[1].read_text()


def test_exit_zero_without_fail_on_change(tmp_path, capsys, fake_network):
    cli.main(_args(tmp_path))
    assert cli.main(_args(tmp_path)) == cli.EXIT_OK


def test_compare_previous_and_no_report(tmp_path, capsys, fake_network):
    cli.main(_args(tmp_path))
    cli.main(_args(tmp_path))
    capsys.readouterr()
    code = cli.main(_args(tmp_path, "--compare", "previous", "--no-report", "--fail-on-change"))
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK  # third scan is identical to the second
    assert "Changes vs scan #2" in out
    assert "No changes." in out
    assert len(list((tmp_path / "reports").glob("*.md"))) == 2


def test_json_output(tmp_path, capsys, fake_network):
    cli.main(_args(tmp_path))
    capsys.readouterr()
    assert cli.main(_args(tmp_path, "--json")) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["scan"]["id"] == 2
    assert payload["diff"]["has_alerts"] is True
    assert [d["ip"] for d in payload["diff"]["new_devices"]] == ["192.168.1.50"]


def test_set_baseline_flag(tmp_path, capsys, fake_network):
    cli.main(_args(tmp_path))
    cli.main(_args(tmp_path, "--set-baseline"))
    capsys.readouterr()
    assert cli.main(["baseline", "--db", str(tmp_path / "netmon.db")]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "Baseline: scan #2" in out
    assert "192.168.1.50" in out


def test_options_are_forwarded(tmp_path, fake_network, capsys):
    cli.main(_args(tmp_path, "--ports", "22,80", "--method", "ping", "--no-hostnames",
                   "--ping-timeout", "0.3", "--port-timeout", "0.2", "--workers", "8"))
    call = fake_network[0]
    assert call["ports"] == [22, 80]
    assert call["method"] == "ping"
    assert call["resolve_names"] is False
    assert call["ping_timeout"] == 0.3 and call["port_timeout"] == 0.2 and call["workers"] == 8


def test_subnet_override(tmp_path, monkeypatch, fake_network, capsys):
    monkeypatch.setattr(cli, "local_network_from_cidr", lambda cidr: LocalNetwork("en0", "10.9.8.7", ipaddress.IPv4Network(cidr), None))
    cli.main(_args(tmp_path, "--subnet", "10.9.8.0/26"))
    assert fake_network[0]["local"].cidr == "10.9.8.0/26"
    assert "10.9.8.0/26" in capsys.readouterr().out


def test_subnet_too_large_is_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "local_network_from_cidr", lambda cidr: LocalNetwork("en0", "", ipaddress.IPv4Network(cidr), None))
    code = cli.main(_args(tmp_path, "--subnet", "10.0.0.0/16"))
    assert code == cli.EXIT_ERROR
    assert "--max-hosts" in capsys.readouterr().err


def test_detection_error_is_reported(tmp_path, monkeypatch, capsys):
    def boom(interface=None):
        raise NetworkDetectionError("Could not find the default network interface. Pass --subnet")

    monkeypatch.setattr(cli, "detect_network", boom)
    assert cli.main(_args(tmp_path)) == cli.EXIT_ERROR
    assert "Pass --subnet" in capsys.readouterr().err


def test_discovery_error_is_reported(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "detect_network", lambda interface=None: LOCAL)

    def boom(*args, **kwargs):
        raise DiscoveryError("ARP scanning needs raw sockets. Re-run with sudo, or use --method ping.")

    monkeypatch.setattr(cli, "run_scan", boom)
    assert cli.main(_args(tmp_path, "--method", "arp")) == cli.EXIT_ERROR
    assert "sudo" in capsys.readouterr().err


def test_bad_port_spec(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "detect_network", lambda interface=None: LOCAL)
    assert cli.main(_args(tmp_path, "--ports", "99999")) == cli.EXIT_ERROR
    assert "Port out of range" in capsys.readouterr().err


def test_history_show_and_baseline_commands(tmp_path, capsys, fake_network):
    db = str(tmp_path / "netmon.db")
    assert cli.main(["history", "--db", db]) == cli.EXIT_OK
    assert "No scans recorded yet" in capsys.readouterr().out

    cli.main(_args(tmp_path))
    cli.main(_args(tmp_path))
    capsys.readouterr()

    assert cli.main(["history", "--db", db]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "Baseline" in out
    lines = [l for l in out.splitlines() if l.strip()]
    assert lines[2].startswith("2 ") and lines[3].startswith("1 ")
    assert "yes" in lines[3]

    assert cli.main(["show", "1", "--db", db]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "scan #1 of 192.168.1.0/24" in out and "192.168.1.30" in out
    assert "Saved as BASELINE" not in out

    assert cli.main(["show", "9", "--db", db]) == cli.EXIT_ERROR
    assert "No scan with id 9" in capsys.readouterr().err

    assert cli.main(["baseline", "--db", db, "--use", "2"]) == cli.EXIT_OK
    assert "Scan #2 is now the baseline" in capsys.readouterr().out

    assert cli.main(["baseline", "--db", db, "--clear"]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["baseline", "--db", db]) == cli.EXIT_OK
    assert "No baseline yet" in capsys.readouterr().out


def test_oui_update_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "update_oui_database", lambda dest: 12345)
    assert cli.main(["oui-update", "--dest", str(tmp_path / "oui.csv")]) == cli.EXIT_OK
    assert "12345" in capsys.readouterr().out


def test_normalize_argv():
    assert cli._normalize_argv([]) == ["scan"]
    assert cli._normalize_argv(["--subnet", "10.0.0.0/24"]) == ["scan", "--subnet", "10.0.0.0/24"]
    assert cli._normalize_argv(["history"]) == ["history"]
    assert cli._normalize_argv(["--help"]) == ["--help"]


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "netmon" in capsys.readouterr().out
