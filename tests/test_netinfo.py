import ipaddress

import pytest

from netmon import netinfo

MAC_ROUTE = """   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""

LINUX_ROUTE = "default via 192.168.1.1 dev wlp3s0 proto dhcp metric 600\n"

MAC_IFCONFIG = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether 3c:22:fb:aa:bb:cc
	inet6 fe80::1c2b:3d4e:5f60:7a8b%en0 prefixlen 64 secured scopeid 0xb
	inet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
"""

LINUX_IFCONFIG = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.5  netmask 255.255.254.0  broadcast 10.0.1.255
        ether 02:42:0a:00:00:05  txqueuelen 0  (Ethernet)
"""

IP_ADDR = """3: wlp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 8c:8d:28:12:34:56 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.42/24 brd 192.168.0.255 scope global dynamic noprefixroute wlp3s0
       valid_lft 85347sec preferred_lft 85347sec
"""


def test_parse_default_interface_macos():
    assert netinfo.parse_default_interface(MAC_ROUTE) == "en0"


def test_parse_default_interface_linux():
    assert netinfo.parse_default_interface(LINUX_ROUTE) == "wlp3s0"


def test_parse_default_interface_missing():
    assert netinfo.parse_default_interface("") is None


@pytest.mark.parametrize(
    "mask,prefix",
    [("0xffffff00", 24), ("255.255.255.0", 24), ("255.255.254.0", 23), ("0xffff0000", 16), ("24", 24)],
)
def test_netmask_to_prefix(mask, prefix):
    assert netinfo.netmask_to_prefix(mask) == prefix


def test_parse_interface_config_macos():
    assert netinfo.parse_interface_config(MAC_IFCONFIG) == {
        "ip": "192.168.1.10",
        "prefix": 24,
        "mac": "3c:22:fb:aa:bb:cc",
    }


def test_parse_interface_config_linux_ifconfig():
    assert netinfo.parse_interface_config(LINUX_IFCONFIG) == {
        "ip": "10.0.0.5",
        "prefix": 23,
        "mac": "02:42:0a:00:00:05",
    }


def test_parse_interface_config_ip_addr():
    assert netinfo.parse_interface_config(IP_ADDR) == {
        "ip": "192.168.0.42",
        "prefix": 24,
        "mac": "8c:8d:28:12:34:56",
    }


def test_parse_interface_config_no_ipv4():
    assert netinfo.parse_interface_config("en1: flags=8863 mtu 1500\n\tether aa:bb:cc:dd:ee:ff\n") is None


def test_detect_network_macos(monkeypatch):
    monkeypatch.setattr(netinfo, "is_macos", lambda: True)

    def fake_run(args, timeout=10.0):
        if args[:3] == ["route", "-n", "get"]:
            return MAC_ROUTE
        if args == ["ifconfig", "en0"]:
            return MAC_IFCONFIG
        return ""

    monkeypatch.setattr(netinfo, "run_command", fake_run)
    local = netinfo.detect_network()
    assert local.interface == "en0"
    assert local.ip == "192.168.1.10"
    assert local.mac == "3c:22:fb:aa:bb:cc"
    assert local.network == ipaddress.IPv4Network("192.168.1.0/24")
    assert local.cidr == "192.168.1.0/24"


def test_detect_network_explicit_interface(monkeypatch):
    monkeypatch.setattr(netinfo, "is_macos", lambda: False)

    def fake_run(args, timeout=10.0):
        if args[0] == "ifconfig":
            return ""
        if args[:3] == ["ip", "-4", "addr"] and args[-1] == "wlp3s0":
            return IP_ADDR
        return ""

    monkeypatch.setattr(netinfo, "run_command", fake_run)
    local = netinfo.detect_network("wlp3s0")
    assert local.cidr == "192.168.0.0/24"
    assert local.ip == "192.168.0.42"


def test_detect_network_no_interface(monkeypatch):
    monkeypatch.setattr(netinfo, "run_command", lambda args, timeout=10.0: "")
    with pytest.raises(netinfo.NetworkDetectionError, match="--subnet"):
        netinfo.detect_network()


def test_detect_network_no_ipv4(monkeypatch):
    monkeypatch.setattr(netinfo, "is_macos", lambda: True)

    def fake_run(args, timeout=10.0):
        return MAC_ROUTE if args[0] == "route" else "en0: flags=8863 mtu 1500\n"

    monkeypatch.setattr(netinfo, "run_command", fake_run)
    with pytest.raises(netinfo.NetworkDetectionError, match="no IPv4 address"):
        netinfo.detect_network()


def test_local_network_from_cidr_uses_detected_host_when_inside(monkeypatch):
    detected = netinfo.LocalNetwork("en0", "192.168.1.10", ipaddress.IPv4Network("192.168.1.0/24"), "3c:22:fb:aa:bb:cc")
    monkeypatch.setattr(netinfo, "detect_network", lambda interface=None: detected)
    local = netinfo.local_network_from_cidr("192.168.1.0/25")
    assert local.cidr == "192.168.1.0/25"
    assert local.ip == "192.168.1.10"
    assert local.mac == "3c:22:fb:aa:bb:cc"


def test_local_network_from_cidr_when_detection_fails(monkeypatch):
    def boom(interface=None):
        raise netinfo.NetworkDetectionError("nope")

    monkeypatch.setattr(netinfo, "detect_network", boom)
    local = netinfo.local_network_from_cidr("10.0.0.0/24")
    assert local.cidr == "10.0.0.0/24"
    assert local.interface == "unknown"
    assert local.ip == ""


def test_run_command_missing_binary():
    assert netinfo.run_command(["definitely-not-a-real-binary-xyz", "-a"]) == ""
