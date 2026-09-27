import ipaddress
from datetime import datetime

import pytest

from netmon import scanner
from netmon.netinfo import LocalNetwork
from netmon.scanner import (
    COMMON_PORTS,
    EXTENDED_PORTS,
    DiscoveryError,
    choose_method,
    discover_arp,
    discover_ping,
    parse_arp_table,
    parse_port_spec,
    ping_command,
    ping_sweep,
    resolve_hostnames,
    run_scan,
    scan_all_ports,
    scan_ports,
)

LOCAL = LocalNetwork("en0", "192.168.1.10", ipaddress.IPv4Network("192.168.1.0/28"), "3c:22:fb:aa:bb:cc")

MAC_ARP = """? (192.168.1.1) at a4:2b:8c:1:34:56 on en0 ifscope [ethernet]
pi.local (192.168.1.20) at b8:27:eb:12:34:56 on en0 ifscope [ethernet]
? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (239.255.255.250) at 1:0:5e:7f:ff:fa on en0 ifscope permanent [ethernet]
"""

LINUX_ARP = """_gateway (192.168.1.1) at a4:2b:8c:01:34:56 [ether] on eth0
? (192.168.1.7) at <incomplete> on eth0
pi (192.168.1.20) at b8:27:eb:12:34:56 [ether] on eth0
"""

IP_NEIGH = """192.168.1.1 dev eth0 lladdr a4:2b:8c:01:34:56 REACHABLE
192.168.1.7 dev eth0 FAILED
192.168.1.20 dev eth0 lladdr b8:27:eb:12:34:56 STALE
fe80::1 dev eth0 lladdr a4:2b:8c:01:34:56 router REACHABLE
"""


# --- port specs ------------------------------------------------------------- #


def test_parse_port_spec_default_and_presets():
    assert parse_port_spec(None) == COMMON_PORTS
    assert parse_port_spec("") == COMMON_PORTS
    assert parse_port_spec("common") == COMMON_PORTS
    assert parse_port_spec("EXTENDED") == EXTENDED_PORTS
    assert set(COMMON_PORTS) < set(EXTENDED_PORTS)


def test_parse_port_spec_lists_and_ranges():
    assert parse_port_spec("443, 22,80,8000-8002") == [22, 80, 443, 8000, 8001, 8002]
    assert parse_port_spec("8002-8000") == [8000, 8001, 8002]
    assert parse_port_spec("22,22,22") == [22]
    combined = parse_port_spec("common,9999")
    assert 9999 in combined and 22 in combined


@pytest.mark.parametrize("bad", ["0", "70000", "22-70000", "abc", ",,"])
def test_parse_port_spec_invalid(bad):
    with pytest.raises(ValueError):
        parse_port_spec(bad)


# --- arp table -------------------------------------------------------------- #


def test_parse_arp_table_macos():
    table = parse_arp_table(MAC_ARP)
    assert set(table) == {"192.168.1.1", "192.168.1.20"}
    assert table["192.168.1.1"].mac == "a4:2b:8c:01:34:56"
    assert table["192.168.1.1"].hostname is None
    assert table["192.168.1.20"].hostname == "pi.local"


def test_parse_arp_table_linux():
    table = parse_arp_table(LINUX_ARP)
    assert set(table) == {"192.168.1.1", "192.168.1.20"}
    assert table["192.168.1.1"].hostname is None  # `_gateway` is a resolver alias, not a real name
    assert table["192.168.1.20"].hostname == "pi"


def test_parse_arp_table_ip_neigh():
    table = parse_arp_table(IP_NEIGH)
    assert set(table) == {"192.168.1.1", "192.168.1.20"}
    assert table["192.168.1.20"].mac == "b8:27:eb:12:34:56"


def test_parse_arp_table_empty():
    assert parse_arp_table("") == {}


# --- ping ------------------------------------------------------------------- #


def test_ping_command_macos_uses_milliseconds(monkeypatch):
    monkeypatch.setattr(scanner, "is_macos", lambda: True)
    cmd = ping_command("192.168.1.5", 1.5)
    assert cmd[0] == "ping" and cmd[-1] == "192.168.1.5"
    assert "-W" in cmd and cmd[cmd.index("-W") + 1] == "1500"
    assert "-t" in cmd and cmd[cmd.index("-t") + 1] == "2"


def test_ping_command_linux_uses_seconds(monkeypatch):
    monkeypatch.setattr(scanner, "is_macos", lambda: False)
    cmd = ping_command("192.168.1.5", 0.4)
    assert cmd[cmd.index("-W") + 1] == "1"
    assert "-t" not in cmd


def test_ping_host_handles_missing_binary(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("ping")

    monkeypatch.setattr(scanner.subprocess, "run", boom)
    assert scanner.ping_host("192.168.1.5") is False


def test_ping_sweep_collects_alive_hosts():
    alive = {"192.168.1.1", "192.168.1.3"}
    calls = []

    def fake_ping(ip, timeout):
        calls.append(ip)
        if ip == "192.168.1.9":
            raise RuntimeError("simulated failure")
        return ip in alive

    result = ping_sweep([f"192.168.1.{i}" for i in range(1, 11)], timeout=0.1, workers=4, ping_fn=fake_ping)
    assert result == alive
    assert len(calls) == 10


def test_ping_sweep_empty():
    assert ping_sweep([], ping_fn=lambda ip, t: True) == set()


# --- discovery -------------------------------------------------------------- #


def test_discover_ping_merges_ping_arp_and_self(monkeypatch):
    monkeypatch.setattr(scanner.socket, "gethostname", lambda: "my-mac.local")
    alive = {"192.168.1.1", "192.168.1.5"}  # .5 answers ping but has no ARP entry
    messages = []
    devices = discover_ping(
        LOCAL,
        ping_fn=lambda ip, t: ip in alive,
        arp_reader=lambda: parse_arp_table(MAC_ARP),
        progress=messages.append,
    )
    by_ip = {d.ip: d for d in devices}
    assert [d.ip for d in devices] == ["192.168.1.1", "192.168.1.5", "192.168.1.10"]
    assert by_ip["192.168.1.1"].mac == "a4:2b:8c:01:34:56" and by_ip["192.168.1.1"].source == "ping"
    assert by_ip["192.168.1.5"].mac is None and by_ip["192.168.1.5"].source == "ping"
    assert by_ip["192.168.1.10"].source == "self"
    assert by_ip["192.168.1.10"].mac == "3c:22:fb:aa:bb:cc"
    assert by_ip["192.168.1.10"].hostname == "my-mac.local"
    # 192.168.1.20 is outside the /28 under test, so the ARP-cache entry is ignored
    assert "192.168.1.20" not in by_ip
    assert messages and "Pinging 14 addresses" in messages[0]


def test_discover_ping_includes_arp_cache_only_hosts():
    local = LocalNetwork("en0", "192.168.1.10", ipaddress.IPv4Network("192.168.1.0/24"), "3c:22:fb:aa:bb:cc")
    devices = discover_ping(local, ping_fn=lambda ip, t: False, arp_reader=lambda: parse_arp_table(MAC_ARP))
    by_ip = {d.ip: d for d in devices}
    assert by_ip["192.168.1.20"].source == "arp-cache"
    assert by_ip["192.168.1.20"].hostname == "pi.local"


def test_discover_ping_self_merges_into_ping_hit(monkeypatch):
    monkeypatch.setattr(scanner.socket, "gethostname", lambda: "my-mac.local")
    devices = discover_ping(LOCAL, ping_fn=lambda ip, t: ip == "192.168.1.10", arp_reader=dict)
    assert len(devices) == 1
    assert devices[0].source == "self" and devices[0].mac == "3c:22:fb:aa:bb:cc"


def test_discover_arp_with_injected_scan():
    devices = discover_arp(
        LOCAL,
        arp_fn=lambda local, timeout: [("192.168.1.1", "A4:2B:8C:01:34:56"), ("192.168.1.3", "junk")],
    )
    assert [(d.ip, d.mac, d.source) for d in devices] == [
        ("192.168.1.1", "a4:2b:8c:01:34:56", "arp"),
        ("192.168.1.10", "3c:22:fb:aa:bb:cc", "self"),
    ]


def test_discover_arp_requires_scapy(monkeypatch):
    monkeypatch.setattr(scanner, "scapy_available", lambda: False)
    with pytest.raises(DiscoveryError, match="scapy"):
        discover_arp(LOCAL)


def test_discover_arp_requires_root(monkeypatch):
    monkeypatch.setattr(scanner, "scapy_available", lambda: True)
    monkeypatch.setattr(scanner, "is_root", lambda: False)
    with pytest.raises(DiscoveryError, match="sudo"):
        discover_arp(LOCAL)


def test_choose_method(monkeypatch):
    assert choose_method("ping")[0] == "ping"
    assert choose_method("arp")[0] == "arp"
    monkeypatch.setattr(scanner, "is_root", lambda: True)
    monkeypatch.setattr(scanner, "scapy_available", lambda: True)
    assert choose_method("auto")[0] == "arp"
    monkeypatch.setattr(scanner, "scapy_available", lambda: False)
    assert choose_method("auto")[0] == "ping"
    monkeypatch.setattr(scanner, "is_root", lambda: False)
    assert choose_method("auto")[0] == "ping"
    with pytest.raises(ValueError):
        choose_method("magic")


# --- hostnames -------------------------------------------------------------- #


def test_resolve_hostnames_with_fake_resolver():
    names = {"192.168.1.1": "router.local"}

    def resolver(ip):
        if ip == "192.168.1.9":
            raise OSError("boom")
        return names.get(ip)

    result = resolve_hostnames(["192.168.1.1", "192.168.1.2", "192.168.1.9"], resolver=resolver)
    assert result == {"192.168.1.1": "router.local"}
    assert resolve_hostnames([], resolver=resolver) == {}


def test_reverse_lookup_failure_returns_none(monkeypatch):
    def boom(ip):
        raise scanner.socket.herror("unknown host")

    monkeypatch.setattr(scanner.socket, "gethostbyaddr", boom)
    assert scanner.reverse_lookup("192.0.2.1") is None


# --- ports ------------------------------------------------------------------ #


def test_scan_all_ports_with_fake_checker():
    open_pairs = {("192.168.1.1", 80), ("192.168.1.1", 443), ("192.168.1.20", 22)}

    def checker(ip, port, timeout):
        if port == 23:
            raise OSError("simulated")
        return (ip, port) in open_pairs

    result = scan_all_ports(["192.168.1.1", "192.168.1.20", "192.168.1.30"], [443, 80, 22, 23], checker=checker)
    assert result == {"192.168.1.1": [80, 443], "192.168.1.20": [22], "192.168.1.30": []}


def test_scan_ports_single_host():
    assert scan_ports("10.0.0.1", [1, 2, 3], checker=lambda ip, p, t: p != 2) == [1, 3]


def test_scan_all_ports_nothing_to_do():
    assert scan_all_ports([], [22], checker=lambda *a: True) == {}
    assert scan_all_ports(["10.0.0.1"], [], checker=lambda *a: True) == {"10.0.0.1": []}


def test_check_port_closed_locally():
    # Port 1 on localhost is essentially never listening; must return False, not raise.
    assert scanner.check_port("127.0.0.1", 1, timeout=0.2) is False


# --- orchestration ---------------------------------------------------------- #


def test_run_scan_end_to_end_with_mocks(vendors):
    ticks = iter([datetime(2026, 9, 26, 12, 0, 0), datetime(2026, 9, 26, 12, 0, 8)])
    from netmon.models import Device

    def discover(local):
        return [
            Device(ip="192.168.1.1", mac="A4:2B:8C:1:34:56", source="ping"),
            Device(ip="192.168.1.10", mac="3c:22:fb:aa:bb:cc", hostname="my-mac.local", source="self"),
            Device(ip="192.168.1.40", mac="da:12:34:56:78:9a", source="arp-cache"),
        ]

    open_pairs = {("192.168.1.1", 80), ("192.168.1.1", 443), ("192.168.1.10", 7000)}
    messages = []
    result = run_scan(
        LOCAL,
        [80, 443, 7000],
        method="ping",
        vendors=vendors,
        progress=messages.append,
        discover_fn=discover,
        port_checker=lambda ip, port, t: (ip, port) in open_pairs,
        resolver=lambda ip: {"192.168.1.1": "router.local"}.get(ip),
        now=lambda: next(ticks),
    )
    assert result.subnet == "192.168.1.0/28"
    assert result.method == "ping"
    assert result.ports_scanned == [80, 443, 7000]
    assert result.duration_seconds == 8.0
    by_ip = {d.ip: d for d in result.devices}
    assert by_ip["192.168.1.1"].mac == "a4:2b:8c:01:34:56"  # normalised
    assert by_ip["192.168.1.1"].vendor == "Netgear"
    assert by_ip["192.168.1.1"].hostname == "router.local"
    assert by_ip["192.168.1.1"].open_ports == [80, 443]
    assert by_ip["192.168.1.10"].vendor == "Apple"
    assert by_ip["192.168.1.10"].hostname == "my-mac.local"  # existing hostname kept
    assert by_ip["192.168.1.10"].open_ports == [7000]
    assert by_ip["192.168.1.40"].vendor == "Private (randomized MAC)"
    assert by_ip["192.168.1.40"].open_ports == []
    assert any("Found 3 device(s)" in m for m in messages)


def test_run_scan_skips_hostnames_and_ports_when_asked(vendors):
    from netmon.models import Device

    result = run_scan(
        LOCAL,
        [],
        method="ping",
        vendors=vendors,
        resolve_names=False,
        discover_fn=lambda local: [Device(ip="192.168.1.1", mac="a4:2b:8c:01:34:56")],
        port_checker=lambda *a: pytest.fail("port checker should not run"),
        resolver=lambda ip: pytest.fail("resolver should not run"),
    )
    assert result.devices[0].hostname is None
    assert result.devices[0].open_ports == []


def test_run_scan_uses_ping_backend(monkeypatch, vendors):
    monkeypatch.setattr(scanner, "discover_ping", lambda local, **kw: [])
    result = run_scan(LOCAL, [22], method="ping", vendors=vendors, port_checker=lambda *a: False)
    assert result.devices == [] and result.method == "ping"
