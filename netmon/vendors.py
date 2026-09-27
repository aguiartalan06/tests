"""MAC address -> vendor lookup using IEEE OUI prefixes.

Two sources are consulted, most specific first:

1. ``~/.netmon/oui.csv`` - the full IEEE registry, downloaded on demand with
   ``netmon oui-update`` (about 50k entries).
2. ``netmon/data/oui.txt`` - a small curated list of common consumer vendors
   bundled with the project so the tool is useful offline.

Modern phones and laptops randomise their Wi-Fi MAC per network. Those
addresses have the "locally administered" bit set and are never in the IEEE
registry, so they are reported as such instead of "Unknown".
"""

from __future__ import annotations

import csv
import os
import urllib.request
from pathlib import Path
from typing import Dict, Optional

IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
BUNDLED_OUI_FILE = Path(__file__).with_name("data") / "oui.txt"
USER_DATA_DIR = Path(os.environ.get("NETMON_HOME", Path.home() / ".netmon"))
USER_OUI_FILE = USER_DATA_DIR / "oui.csv"

RANDOMIZED_LABEL = "Private (randomized MAC)"
UNKNOWN_LABEL = "Unknown"


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Return ``aa:bb:cc:dd:ee:ff`` for any common MAC spelling, else None.

    macOS ``arp -a`` prints unpadded octets (``0:1c:b3:9:2a:ff``), Windows
    uses dashes and some tools use dots or no separators at all.
    """
    if not mac:
        return None
    cleaned = mac.strip().lower()
    if cleaned in ("(incomplete)", "incomplete", "<incomplete>"):
        return None
    if ":" in cleaned or "-" in cleaned:
        parts = cleaned.replace("-", ":").split(":")
    elif "." in cleaned:
        hexstr = cleaned.replace(".", "")
        if len(hexstr) != 12:
            return None
        parts = [hexstr[i : i + 2] for i in range(0, 12, 2)]
    else:
        if len(cleaned) != 12:
            return None
        parts = [cleaned[i : i + 2] for i in range(0, 12, 2)]
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    return ":".join(f"{o:02x}" for o in octets)


def is_locally_administered(mac: str) -> bool:
    """True when the MAC was generated locally (privacy/randomized address)."""
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    first_octet = int(normalized[:2], 16)
    return bool(first_octet & 0x02)


def oui_prefix(mac: str) -> Optional[str]:
    normalized = normalize_mac(mac)
    if not normalized:
        return None
    return normalized[:8].replace(":", "").upper()


def _load_bundled(path: Path) -> Dict[str, str]:
    table: Dict[str, str] = {}
    if not path.exists():
        return table
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            prefix, _, vendor = line.partition("\t")
            if not vendor:
                prefix, _, vendor = line.partition(" ")
            prefix = prefix.strip().upper().replace(":", "").replace("-", "")
            if len(prefix) == 6 and vendor.strip():
                table[prefix] = vendor.strip()
    return table


def _load_ieee_csv(path: Path) -> Dict[str, str]:
    """Parse the IEEE ``oui.csv`` format (Registry,Assignment,Organization Name,...)."""
    table: Dict[str, str] = {}
    if not path.exists():
        return table
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 3:
                continue
            assignment, vendor = row[1].strip().upper(), row[2].strip()
            if assignment == "ASSIGNMENT" or len(assignment) != 6:
                continue
            table[assignment] = vendor
    return table


class VendorLookup:
    """Resolve MAC addresses to vendor names."""

    def __init__(
        self,
        bundled_file: Path = BUNDLED_OUI_FILE,
        user_file: Optional[Path] = USER_OUI_FILE,
        extra: Optional[Dict[str, str]] = None,
    ) -> None:
        self._table: Dict[str, str] = {}
        self._table.update(_load_bundled(bundled_file))
        if user_file is not None:
            self._table.update(_load_ieee_csv(user_file))
        if extra:
            self._table.update({k.upper(): v for k, v in extra.items()})

    def __len__(self) -> int:
        return len(self._table)

    def lookup(self, mac: Optional[str]) -> str:
        if not mac:
            return UNKNOWN_LABEL
        prefix = oui_prefix(mac)
        if prefix is None:
            return UNKNOWN_LABEL
        vendor = self._table.get(prefix)
        if vendor:
            return vendor
        if is_locally_administered(mac):
            return RANDOMIZED_LABEL
        return UNKNOWN_LABEL


def update_oui_database(destination: Path = USER_OUI_FILE, url: str = IEEE_OUI_CSV_URL) -> int:
    """Download the IEEE OUI registry. Returns the number of entries saved."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "netmon/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 (fixed https URL)
        data = response.read()
    tmp = destination.with_suffix(".tmp")
    tmp.write_bytes(data)
    entries = _load_ieee_csv(tmp)
    if not entries:
        tmp.unlink(missing_ok=True)
        raise ValueError("Downloaded file did not look like the IEEE oui.csv registry")
    tmp.replace(destination)
    return len(entries)
