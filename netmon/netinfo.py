"""Local network information: default interface, address, netmask, MAC.

Everything that shells out lives here so the rest of the code (and the tests)
can work with plain strings. The parsers are pure functions and are tested
against captured macOS and Linux command output.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional


class NetworkDetectionError(RuntimeError):
    """Raised when the local subnet cannot be determined automatically."""


@dataclass
class LocalNetwork:
    interface: str
    ip: str
    network: ipaddress.IPv4Network
    mac: Optional[str] = None

    @property
    def cidr(self) -> str:
        return str(self.network)


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_root() -> bool:
    getuid = getattr(os, "geteuid", None)
    return bool(getuid and getuid() == 0)


def run_command(args: List[str], timeout: float = 10.0) -> str:
    """Run a command and return its stdout (empty string on any failure)."""
    if shutil.which(args[0]) is None:
        return ""
    try:
        completed = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout or ""


# --------------------------------------------------------------------------- #
# Parsers (pure functions)
# --------------------------------------------------------------------------- #

_MAC_ROUTE_IFACE = re.compile(r"^\s*interface:\s*(\S+)", re.MULTILINE)
_LINUX_ROUTE_IFACE = re.compile(r"\bdev\s+(\S+)")

# macOS ifconfig:  inet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
# Linux ifconfig:  inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
_IFCONFIG_INET = re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)")
_IFCONFIG_ETHER = re.compile(r"\b(?:ether|HWaddr)\s+([0-9a-fA-F:]{17})")
# Linux `ip -4 addr`:  inet 192.168.1.23/24 brd 192.168.1.255 scope global eth0
_IP_ADDR_INET = re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)")
_IP_ADDR_ETHER = re.compile(r"\blink/ether\s+([0-9a-fA-F:]{17})")


def parse_default_interface(route_output: str) -> Optional[str]:
    """Extract the interface name from `route -n get default` (macOS) or
    `ip route show default` (Linux) output."""
    match = _MAC_ROUTE_IFACE.search(route_output)
    if match:
        return match.group(1)
    match = _LINUX_ROUTE_IFACE.search(route_output)
    if match:
        return match.group(1)
    return None


def netmask_to_prefix(netmask: str) -> int:
    """Accept `0xffffff00`, `255.255.255.0` or a bare prefix length like `24`."""
    netmask = netmask.strip()
    if netmask.lower().startswith("0x"):
        value = int(netmask, 16)
    elif "." in netmask:
        value = int(ipaddress.IPv4Address(netmask))
    else:
        return int(netmask)
    return bin(value).count("1")


def parse_interface_config(text: str) -> Optional[dict]:
    """Parse `ifconfig <iface>` or `ip -4 addr show <iface>` output.

    Returns ``{"ip": str, "prefix": int, "mac": Optional[str]}`` or ``None``
    when no IPv4 address is present.
    """
    ip: Optional[str] = None
    prefix: Optional[int] = None
    mac: Optional[str] = None

    match = _IFCONFIG_INET.search(text)
    if match:
        ip = match.group(1)
        prefix = netmask_to_prefix(match.group(2))
    else:
        match = _IP_ADDR_INET.search(text)
        if match:
            ip = match.group(1)
            prefix = int(match.group(2))

    if ip is None or prefix is None:
        return None

    match = _IFCONFIG_ETHER.search(text) or _IP_ADDR_ETHER.search(text)
    if match:
        mac = match.group(1).lower()

    return {"ip": ip, "prefix": prefix, "mac": mac}


# --------------------------------------------------------------------------- #
# Detection (shells out)
# --------------------------------------------------------------------------- #


def default_interface() -> Optional[str]:
    if is_macos():
        return parse_default_interface(run_command(["route", "-n", "get", "default"]))
    return parse_default_interface(run_command(["ip", "route", "show", "default"]))


def interface_config(interface: str) -> Optional[dict]:
    output = run_command(["ifconfig", interface])
    if not output:
        output = run_command(["ip", "-4", "addr", "show", "dev", interface])
    if not output:
        return None
    return parse_interface_config(output)


def detect_network(interface: Optional[str] = None) -> LocalNetwork:
    """Work out which subnet this machine is on.

    Raises NetworkDetectionError with a helpful message if it cannot, so the
    CLI can tell the user to pass ``--subnet`` explicitly.
    """
    iface = interface or default_interface()
    if not iface:
        raise NetworkDetectionError(
            "Could not find the default network interface. "
            "Pass --subnet (e.g. --subnet 192.168.1.0/24) or --interface."
        )
    config = interface_config(iface)
    if not config:
        raise NetworkDetectionError(
            f"Interface {iface} has no IPv4 address. "
            "Are you connected to Wi-Fi? You can also pass --subnet explicitly."
        )
    network = ipaddress.IPv4Network(f"{config['ip']}/{config['prefix']}", strict=False)
    return LocalNetwork(interface=iface, ip=config["ip"], network=network, mac=config["mac"])


def local_network_from_cidr(cidr: str, local_ip: Optional[str] = None) -> LocalNetwork:
    """Build a LocalNetwork from a user-supplied CIDR (used with --subnet)."""
    network = ipaddress.IPv4Network(cidr, strict=False)
    detected: Optional[LocalNetwork] = None
    try:
        detected = detect_network()
    except NetworkDetectionError:
        pass
    if detected and ipaddress.IPv4Address(detected.ip) in network:
        return LocalNetwork(detected.interface, detected.ip, network, detected.mac)
    return LocalNetwork(
        interface=detected.interface if detected else "unknown",
        ip=local_ip or "",
        network=network,
        mac=None,
    )
