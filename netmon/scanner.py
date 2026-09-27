"""Device discovery and TCP port scanning.

Two discovery back-ends are available:

* ``ping``  - ICMP sweep of every host in the subnet via the system ``ping``
              binary, then a read of the OS ARP cache for MAC addresses.
              Works without sudo on macOS and Linux.
* ``arp``   - Broadcast ARP requests with scapy. Faster and catches hosts that
              drop ICMP, but needs raw sockets, i.e. ``sudo``.

Port scanning is a plain TCP connect() scan and never needs privileges.

Every function that touches the network takes an injectable callable so the
test-suite can run with canned data and no network at all.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from netmon.models import Device, ScanResult
from netmon.netinfo import LocalNetwork, is_macos, is_root, run_command
from netmon.vendors import VendorLookup, normalize_mac

ProgressFn = Callable[[str], None]

# --------------------------------------------------------------------------- #
# Port presets
# --------------------------------------------------------------------------- #

COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 515, 548, 554,
    587, 631, 993, 995, 1883, 1900, 2323, 3000, 3306, 3389, 5000, 5222, 5432,
    5900, 6379, 7000, 8000, 8008, 8080, 8081, 8443, 8883, 9000, 9100, 27017,
    32400, 49152, 62078,
]

EXTENDED_PORTS: List[int] = sorted(set(COMMON_PORTS) | {
    81, 88, 389, 427, 465, 502, 623, 873, 1080, 1443, 1723, 2000, 2049, 2222,
    3001, 3128, 4000, 4443, 5001, 5060, 5555, 5601, 5800, 6000, 6666, 6667,
    7070, 7443, 7547, 8001, 8010, 8088, 8123, 8181, 8200, 8291, 8333, 8888,
    9090, 9091, 9200, 9443, 9999, 10000, 20000, 49153, 51413, 60000,
})

PORT_PRESETS: Dict[str, List[int]] = {
    "common": COMMON_PORTS,
    "extended": EXTENDED_PORTS,
}


def parse_port_spec(spec: Optional[str]) -> List[int]:
    """Turn ``"22,80,8000-8010"`` or a preset name into a sorted port list."""
    if not spec or not spec.strip():
        return list(COMMON_PORTS)
    spec = spec.strip().lower()
    if spec in PORT_PRESETS:
        return list(PORT_PRESETS[spec])
    ports: Set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk in PORT_PRESETS:
            ports.update(PORT_PRESETS[chunk])
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
        else:
            start = end = int(chunk)
        if start < 1 or end > 65535:
            raise ValueError(f"Port out of range in '{chunk}' (1-65535)")
        ports.update(range(start, end + 1))
    if not ports:
        raise ValueError(f"No ports found in spec '{spec}'")
    return sorted(ports)


# --------------------------------------------------------------------------- #
# ARP cache parsing
# --------------------------------------------------------------------------- #


@dataclass
class ArpEntry:
    ip: str
    mac: str
    hostname: Optional[str] = None


# macOS / Linux `arp -a`:
#   router.local (192.168.1.1) at a4:2b:8c:1:34:56 on en0 ifscope [ethernet]
#   ? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]
#   _gateway (192.168.1.1) at a4:2b:8c:01:34:56 [ether] on eth0
_ARP_A_LINE = re.compile(r"^(?P<name>\S+)\s+\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>\S+)")
# Linux `ip neigh`:
#   192.168.1.1 dev eth0 lladdr a4:2b:8c:01:34:56 REACHABLE
_IP_NEIGH_LINE = re.compile(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+(?P<mac>\S+)")


def _is_multicast_or_broadcast(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x01)


def parse_arp_table(text: str) -> Dict[str, ArpEntry]:
    """Parse ``arp -a`` (macOS/Linux) or ``ip neigh`` output into a dict keyed by IP."""
    entries: Dict[str, ArpEntry] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        hostname: Optional[str] = None
        match = _ARP_A_LINE.match(line)
        if match:
            name = match.group("name")
            if name != "?" and not name.startswith("_"):
                hostname = name
        else:
            match = _IP_NEIGH_LINE.match(line)
        if not match:
            continue
        mac = normalize_mac(match.group("mac"))
        if not mac or _is_multicast_or_broadcast(mac):
            continue
        ip = match.group("ip")
        entries[ip] = ArpEntry(ip=ip, mac=mac, hostname=hostname)
    return entries


def read_arp_table() -> Dict[str, ArpEntry]:
    """Read the OS neighbour/ARP cache."""
    output = run_command(["arp", "-a", "-n"])  # -n: skip slow per-entry reverse lookups
    if not output:
        output = run_command(["arp", "-a"])
    if not output:
        output = run_command(["ip", "neigh", "show"])
    return parse_arp_table(output)


# --------------------------------------------------------------------------- #
# Ping sweep
# --------------------------------------------------------------------------- #


def ping_command(ip: str, timeout: float) -> List[str]:
    """Platform-specific one-shot ping. macOS wants milliseconds, Linux seconds."""
    if is_macos():
        wait_ms = max(1, int(timeout * 1000))
        return ["ping", "-n", "-q", "-c", "1", "-W", str(wait_ms), "-t", str(max(1, int(timeout + 0.999))), ip]
    return ["ping", "-n", "-q", "-c", "1", "-W", str(max(1, int(timeout + 0.999))), ip]


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Return True if ``ip`` answered a single ICMP echo request."""
    try:
        completed = subprocess.run(
            ping_command(ip, timeout),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


PingFn = Callable[[str, float], bool]


def ping_sweep(
    hosts: Iterable[str],
    timeout: float = 1.0,
    workers: int = 64,
    ping_fn: PingFn = ping_host,
) -> Set[str]:
    """Ping every host concurrently and return the set that answered."""
    host_list = list(hosts)
    alive: Set[str] = set()
    if not host_list:
        return alive
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(host_list)))) as pool:
        futures = {pool.submit(ping_fn, ip, timeout): ip for ip in host_list}
        for future in as_completed(futures):
            try:
                if future.result():
                    alive.add(futures[future])
            except Exception:  # noqa: BLE001 - one bad host must not abort the sweep
                continue
    return alive


class DiscoveryError(RuntimeError):
    """Raised when a discovery back-end cannot run (missing sudo, scapy, ...)."""


def _self_device(local: LocalNetwork) -> Optional[Device]:
    if not local.ip:
        return None
    try:
        hostname: Optional[str] = socket.gethostname()
    except OSError:
        hostname = None
    return Device(ip=local.ip, mac=normalize_mac(local.mac), hostname=hostname, source="self")


def discover_ping(
    local: LocalNetwork,
    timeout: float = 1.0,
    workers: int = 64,
    ping_fn: PingFn = ping_host,
    arp_reader: Callable[[], Dict[str, ArpEntry]] = read_arp_table,
    progress: Optional[ProgressFn] = None,
) -> List[Device]:
    """Ping sweep + ARP cache. Hosts that never answered ping but are in the
    ARP cache are included with ``source="arp-cache"`` (phones asleep, etc.)."""
    hosts = [str(h) for h in local.network.hosts()]
    if progress:
        progress(f"Pinging {len(hosts)} addresses in {local.cidr} ...")
    alive = ping_sweep(hosts, timeout=timeout, workers=workers, ping_fn=ping_fn)
    arp = arp_reader()

    found: Dict[str, Device] = {}
    for ip in alive:
        entry = arp.get(ip)
        found[ip] = Device(
            ip=ip,
            mac=entry.mac if entry else None,
            hostname=entry.hostname if entry else None,
            source="ping",
        )
    for ip, entry in arp.items():
        if ip in found:
            continue
        try:
            if ipaddress.IPv4Address(ip) not in local.network:
                continue
        except ValueError:
            continue
        found[ip] = Device(ip=ip, mac=entry.mac, hostname=entry.hostname, source="arp-cache")

    me = _self_device(local)
    if me and ipaddress.IPv4Address(me.ip) in local.network:
        existing = found.get(me.ip)
        if existing:
            existing.mac = existing.mac or me.mac
            existing.hostname = existing.hostname or me.hostname
            existing.source = "self"
        else:
            found[me.ip] = me

    return sorted(found.values(), key=lambda d: ipaddress.IPv4Address(d.ip))


def scapy_available() -> bool:
    return importlib.util.find_spec("scapy") is not None


def discover_arp(
    local: LocalNetwork,
    timeout: float = 2.0,
    progress: Optional[ProgressFn] = None,
    arp_fn: Optional[Callable[[LocalNetwork, float], List[Tuple[str, str]]]] = None,
) -> List[Device]:
    """Active ARP scan with scapy (requires root)."""
    if arp_fn is None:
        if not scapy_available():
            raise DiscoveryError("scapy is not installed. Run `pip install scapy` or use --method ping.")
        if not is_root():
            raise DiscoveryError("ARP scanning needs raw sockets. Re-run with sudo, or use --method ping.")
        arp_fn = _scapy_arp_scan

    if progress:
        progress(f"ARP-scanning {local.cidr} ...")
    found: Dict[str, Device] = {}
    for ip, mac in arp_fn(local, timeout):
        normalized = normalize_mac(mac)
        if not normalized:
            continue
        found[ip] = Device(ip=ip, mac=normalized, source="arp")

    me = _self_device(local)
    if me and ipaddress.IPv4Address(me.ip) in local.network:
        found.setdefault(me.ip, me)

    return sorted(found.values(), key=lambda d: ipaddress.IPv4Address(d.ip))


def _scapy_arp_scan(local: LocalNetwork, timeout: float) -> List[Tuple[str, str]]:
    from scapy.all import ARP, Ether, conf, srp  # type: ignore  # lazy import: slow and optional

    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=local.cidr)
    kwargs = {"timeout": timeout, "retry": 1}
    if local.interface and local.interface != "unknown":
        kwargs["iface"] = local.interface
    answered, _ = srp(packet, **kwargs)
    return [(received.psrc, received.hwsrc) for _sent, received in answered]


# --------------------------------------------------------------------------- #
# Hostname resolution
# --------------------------------------------------------------------------- #


def reverse_lookup(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_hostnames(
    ips: Iterable[str],
    timeout: float = 2.0,
    workers: int = 32,
    resolver: Callable[[str], Optional[str]] = reverse_lookup,
) -> Dict[str, str]:
    """Reverse-DNS a batch of IPs with an overall time budget."""
    ip_list = list(ips)
    results: Dict[str, str] = {}
    if not ip_list:
        return results
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(ip_list))))
    futures = {pool.submit(resolver, ip): ip for ip in ip_list}
    try:
        for future in as_completed(futures, timeout=timeout * 3):
            try:
                name = future.result()
            except Exception:  # noqa: BLE001
                name = None
            if name:
                results[futures[future]] = name
    except (FuturesTimeoutError, TimeoutError):  # distinct classes before Python 3.11
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results


# --------------------------------------------------------------------------- #
# Port scanning
# --------------------------------------------------------------------------- #

PortChecker = Callable[[str, int, float], bool]


def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """TCP connect() probe. True when the port accepted the connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan_ports(
    ip: str,
    ports: Iterable[int],
    timeout: float = 0.5,
    workers: int = 64,
    checker: PortChecker = check_port,
) -> List[int]:
    return scan_all_ports([ip], ports, timeout=timeout, workers=workers, checker=checker).get(ip, [])


def scan_all_ports(
    ips: Iterable[str],
    ports: Iterable[int],
    timeout: float = 0.5,
    workers: int = 64,
    checker: PortChecker = check_port,
    progress: Optional[ProgressFn] = None,
) -> Dict[str, List[int]]:
    """Scan every (ip, port) pair through one shared thread pool."""
    ip_list, port_list = list(ips), sorted(set(ports))
    open_ports: Dict[str, List[int]] = {ip: [] for ip in ip_list}
    pairs = [(ip, port) for ip in ip_list for port in port_list]
    if not pairs:
        return open_ports
    if progress:
        progress(f"Scanning {len(port_list)} ports on {len(ip_list)} hosts ({len(pairs)} probes) ...")
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(pairs)))) as pool:
        futures = {pool.submit(checker, ip, port, timeout): (ip, port) for ip, port in pairs}
        for future in as_completed(futures):
            ip, port = futures[future]
            try:
                if future.result():
                    open_ports[ip].append(port)
            except Exception:  # noqa: BLE001
                continue
    for ip in open_ports:
        open_ports[ip].sort()
    return open_ports


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def choose_method(requested: str) -> Tuple[str, str]:
    """Resolve ``auto`` to a concrete back-end and explain the choice."""
    requested = (requested or "auto").lower()
    if requested == "ping":
        return "ping", "ping sweep + ARP cache (no sudo needed)"
    if requested == "arp":
        return "arp", "active ARP scan via scapy (sudo)"
    if requested != "auto":
        raise ValueError(f"Unknown discovery method '{requested}' (use auto, ping or arp)")
    if is_root() and scapy_available():
        return "arp", "active ARP scan via scapy (running as root)"
    if is_root():
        return "ping", "ping sweep (root, but scapy not installed)"
    return "ping", "ping sweep + ARP cache (not root, so no ARP scan)"


DiscoverFn = Callable[[LocalNetwork], List[Device]]


def run_scan(
    local: LocalNetwork,
    ports: Optional[List[int]] = None,
    method: str = "auto",
    *,
    ping_timeout: float = 1.0,
    port_timeout: float = 0.5,
    workers: int = 64,
    resolve_names: bool = True,
    vendors: Optional[VendorLookup] = None,
    progress: Optional[ProgressFn] = None,
    discover_fn: Optional[DiscoverFn] = None,
    port_checker: PortChecker = check_port,
    resolver: Callable[[str], Optional[str]] = reverse_lookup,
    now: Callable[[], datetime] = datetime.now,
) -> ScanResult:
    """Discover devices, enrich them, scan ports and return a ScanResult."""
    ports = list(ports) if ports is not None else list(COMMON_PORTS)
    vendors = vendors or VendorLookup()
    started_at = now()

    if discover_fn is None:
        concrete, reason = choose_method(method)
        if progress:
            progress(f"Discovery method: {reason}")
        if concrete == "arp":
            devices = discover_arp(local, timeout=max(ping_timeout, 1.0), progress=progress)
        else:
            devices = discover_ping(local, timeout=ping_timeout, workers=workers, progress=progress)
    else:
        concrete = method
        devices = discover_fn(local)

    if progress:
        progress(f"Found {len(devices)} device(s).")

    for device in devices:
        device.mac = normalize_mac(device.mac)
        device.vendor = vendors.lookup(device.mac)

    if resolve_names:
        missing = [d.ip for d in devices if not d.hostname]
        if missing and progress:
            progress(f"Resolving hostnames for {len(missing)} device(s) ...")
        names = resolve_hostnames(missing, resolver=resolver) if missing else {}
        for device in devices:
            if not device.hostname and device.ip in names:
                device.hostname = names[device.ip]

    if ports:
        open_by_ip = scan_all_ports(
            [d.ip for d in devices], ports, timeout=port_timeout, workers=workers,
            checker=port_checker, progress=progress,
        )
        for device in devices:
            device.open_ports = open_by_ip.get(device.ip, [])

    return ScanResult(
        subnet=local.cidr,
        started_at=started_at,
        finished_at=now(),
        devices=devices,
        method=concrete,
        ports_scanned=ports,
    )
