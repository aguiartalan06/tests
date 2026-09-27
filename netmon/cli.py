"""Command-line interface.

    netmon                      # same as `netmon scan`
    netmon scan [options]       # discover, port-scan, save, diff, report
    netmon history              # list saved scans
    netmon show <scan-id>       # print the devices from a saved scan
    netmon baseline [--use ID | --clear]
    netmon oui-update           # download the full IEEE vendor list
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from netmon import __version__
from netmon.diff import diff_scans
from netmon.netinfo import NetworkDetectionError, detect_network, local_network_from_cidr
from netmon.report import color_enabled, format_dt, render_console, render_json, render_markdown, render_table, write_report, format_ports
from netmon.scanner import DiscoveryError, parse_port_spec, run_scan
from netmon.storage import DEFAULT_DB_PATH, Storage
from netmon.vendors import USER_OUI_FILE, VendorLookup, update_oui_database

DEFAULT_REPORTS_DIR = Path("reports")
DEFAULT_MAX_HOSTS = 1024
SUBCOMMANDS = ("scan", "history", "show", "baseline", "oui-update")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CHANGES = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netmon",
        description="Home network monitor: discover devices, scan ports, track changes against a baseline.",
    )
    parser.add_argument("--version", action="version", version=f"netmon {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run a scan (default command)")
    scan.add_argument("--subnet", help="CIDR to scan, e.g. 192.168.1.0/24 (default: auto-detect)")
    scan.add_argument("--interface", help="network interface to auto-detect from, e.g. en0")
    scan.add_argument("--ports", default="common",
                      help="ports to probe: 'common' (default), 'extended', or a list like 22,80,443,8000-8100")
    scan.add_argument("--method", choices=("auto", "ping", "arp"), default="auto",
                      help="discovery method: ping sweep (no sudo) or ARP scan via scapy (sudo). auto picks arp when root")
    scan.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path (default: netmon.db)")
    scan.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR), help="where to write markdown reports")
    scan.add_argument("--no-report", action="store_true", help="do not write a markdown report")
    scan.add_argument("--no-hostnames", action="store_true", help="skip reverse-DNS lookups (faster)")
    scan.add_argument("--compare", choices=("baseline", "previous"), default="baseline",
                      help="compare against the baseline (default) or the previous scan")
    scan.add_argument("--set-baseline", action="store_true", help="make this scan the new baseline")
    scan.add_argument("--fail-on-change", action="store_true",
                      help="exit with status 2 when new devices, missing devices or new ports are found (for cron)")
    scan.add_argument("--json", action="store_true", help="print the result as JSON instead of text")
    scan.add_argument("--ping-timeout", type=float, default=1.0, help="seconds to wait for each ping (default 1.0)")
    scan.add_argument("--port-timeout", type=float, default=0.5, help="seconds to wait for each port (default 0.5)")
    scan.add_argument("--workers", type=int, default=64, help="concurrent probes (default 64)")
    scan.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS,
                      help=f"refuse subnets larger than this many addresses (default {DEFAULT_MAX_HOSTS})")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    scan.add_argument("-q", "--quiet", action="store_true", help="suppress progress messages")

    history = sub.add_parser("history", help="list saved scans")
    history.add_argument("--db", default=str(DEFAULT_DB_PATH))
    history.add_argument("--limit", type=int, default=20)

    show = sub.add_parser("show", help="print the devices recorded in a saved scan")
    show.add_argument("scan_id", type=int)
    show.add_argument("--db", default=str(DEFAULT_DB_PATH))

    baseline = sub.add_parser("baseline", help="show, change or clear the baseline")
    baseline.add_argument("--db", default=str(DEFAULT_DB_PATH))
    group = baseline.add_mutually_exclusive_group()
    group.add_argument("--use", type=int, metavar="SCAN_ID", help="promote a saved scan to baseline")
    group.add_argument("--clear", action="store_true", help="forget the baseline; the next scan becomes it")

    oui = sub.add_parser("oui-update", help="download the full IEEE OUI vendor registry")
    oui.add_argument("--dest", default=str(USER_OUI_FILE), help=f"where to store it (default {USER_OUI_FILE})")
    return parser


def _normalize_argv(argv: List[str]) -> List[str]:
    """Let `netmon --subnet ...` mean `netmon scan --subnet ...`."""
    if not argv:
        return ["scan"]
    first = argv[0]
    if first in SUBCOMMANDS or first in ("-h", "--help", "--version"):
        return argv
    if first.startswith("-"):
        return ["scan", *argv]
    return argv


def main(argv: Optional[List[str]] = None) -> int:
    argv = _normalize_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "history":
            return cmd_history(args)
        if args.command == "show":
            return cmd_show(args)
        if args.command == "baseline":
            return cmd_baseline(args)
        if args.command == "oui-update":
            return cmd_oui_update(args)
    except (NetworkDetectionError, DiscoveryError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    parser.print_help()
    return EXIT_ERROR


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


def cmd_scan(args: argparse.Namespace) -> int:
    def progress(message: str) -> None:
        if not args.quiet and not args.json:
            print(message, file=sys.stderr)

    local = local_network_from_cidr(args.subnet) if args.subnet else detect_network(args.interface)
    if local.network.num_addresses > args.max_hosts:
        raise ValueError(
            f"{local.cidr} has {local.network.num_addresses} addresses, more than --max-hosts {args.max_hosts}. "
            "Pass a smaller --subnet or raise --max-hosts."
        )
    ports = parse_port_spec(args.ports)
    progress(f"Local network: {local.cidr} via {local.interface} (this host: {local.ip or 'unknown'})")

    result = run_scan(
        local,
        ports,
        method=args.method,
        ping_timeout=args.ping_timeout,
        port_timeout=args.port_timeout,
        workers=args.workers,
        resolve_names=not args.no_hostnames,
        vendors=VendorLookup(),
        progress=progress,
    )

    with Storage(args.db) as storage:
        storage.save_scan(result, as_baseline=True if args.set_baseline else None)
        reference = None
        if not result.is_baseline:
            reference = storage.get_latest(exclude_id=result.id) if args.compare == "previous" else storage.get_baseline()

    diff = diff_scans(reference, result) if reference is not None else None

    report_path = None
    if not args.no_report:
        report_path = write_report(render_markdown(result, diff), Path(args.reports_dir), result.started_at)

    if args.json:
        print(render_json(result, diff))
    else:
        use_color = color_enabled() and not args.no_color
        print(render_console(result, diff, report_path=report_path, color=use_color))

    if args.fail_on_change and diff is not None and diff.has_alerts:
        return EXIT_CHANGES
    return EXIT_OK


# --------------------------------------------------------------------------- #
# history / show / baseline / oui-update
# --------------------------------------------------------------------------- #


def cmd_history(args: argparse.Namespace) -> int:
    with Storage(args.db) as storage:
        scans = storage.list_scans(limit=args.limit)
    if not scans:
        print("No scans recorded yet. Run `netmon scan` first.")
        return EXIT_OK
    rows = [
        [str(s["id"]), s["started_at"].replace("T", " "), s["subnet"], s["method"], str(s["device_count"]),
         "yes" if s["is_baseline"] else ""]
        for s in scans
    ]
    print(render_table(["ID", "Started", "Subnet", "Method", "Devices", "Baseline"], rows))
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    with Storage(args.db) as storage:
        result = storage.get_scan(args.scan_id)
    if result is None:
        raise KeyError(f"No scan with id {args.scan_id}")
    print(render_console(result, None, color=color_enabled(), show_baseline_notice=False))
    return EXIT_OK


def cmd_baseline(args: argparse.Namespace) -> int:
    with Storage(args.db) as storage:
        if args.clear:
            storage.clear_baseline()
            print("Baseline cleared. The next scan will become the new baseline.")
            return EXIT_OK
        if args.use is not None:
            storage.set_baseline(args.use)
            print(f"Scan #{args.use} is now the baseline.")
            return EXIT_OK
        baseline = storage.get_baseline()
    if baseline is None:
        print("No baseline yet. The first `netmon scan` creates it.")
        return EXIT_OK
    print(f"Baseline: scan #{baseline.id} of {baseline.subnet} at {format_dt(baseline.started_at)}"
          f" ({len(baseline.devices)} devices)")
    rows = [[d.ip, d.mac or "-", d.vendor, d.hostname or "-", format_ports(d.open_ports)] for d in baseline.devices]
    print(render_table(["IP", "MAC", "Vendor", "Hostname", "Open ports"], rows, max_width=40))
    return EXIT_OK


def cmd_oui_update(args: argparse.Namespace) -> int:
    dest = Path(args.dest)
    print(f"Downloading IEEE OUI registry to {dest} ...")
    count = update_oui_database(dest)
    print(f"Saved {count} vendor prefixes.")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
