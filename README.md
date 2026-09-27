# netmon - home network monitor

A small, dependency-light Python tool that keeps an eye on your own home Wi-Fi
network. It discovers every device on the local subnet, checks each one for
open TCP ports, saves the first run as a **baseline** in SQLite, and on every
later run tells you what changed: new devices, devices that disappeared, and
ports that opened up.

Built as a cybersecurity portfolio project. **Only scan networks you own or
have written permission to test.** Port-scanning other people's networks is
illegal in most places.

```
$ ./run.sh   # one week after the baseline run
Home Network Monitor - scan #2 of 192.168.1.0/24
2026-10-03 14:03:11 -> 14:03:28 (17.4s) | discovery: ping | 44 ports probed per host

Devices (6)
IP            MAC                Vendor                     Hostname                  Open ports
------------  -----------------  -------------------------  ------------------------  -----------------------------------
192.168.1.1   a4:2b:8c:01:34:56  Netgear                    router.local              53 (dns), 80 (http), 443 (https)
192.168.1.10  3c:22:fb:aa:bb:cc  Apple                      Talans-MacBook-Pro.local  5000 (upnp/airplay), 7000 (airplay)
192.168.1.20  b8:27:eb:12:34:56  Raspberry Pi Foundation    pi.local                  22 (ssh), 80 (http), 5900 (vnc)
192.168.1.41  da:12:34:56:78:9a  Private (randomized MAC)   -                         62078 (iphone-sync)
192.168.1.50  f0:d2:f1:44:55:66  Amazon Technologies        -                         8080 (http-proxy)
192.168.1.60  18:fe:34:9a:bc:de  Espressif (ESP8266/ESP32)  -                         80 (http), 1883 (mqtt)

Changes vs baseline (2026-09-26 14:03:11)
  [+] NEW DEVICE  192.168.1.50  f0:d2:f1:44:55:66  Amazon Technologies  ports: 8080 (http-proxy)
  [-] MISSING     192.168.1.30  5c:aa:fd:11:22:33  Sonos
  [!] NEW PORTS   192.168.1.20  pi.local: 5900 (vnc)
  [i] ip changed  192.168.1.40 -> 192.168.1.41  Private (randomized MAC)
  3 device(s) unchanged.

Worth a look
  * 192.168.1.20 (pi.local) has 5900 (vnc) open: VNC remote control - check it needs a password
  * 192.168.1.60 (Espressif (ESP8266/ESP32)) has 1883 (mqtt) open: MQTT broker - check it requires authentication

Report written to reports/2026-10-03_140311.md
```

## Features

- **Device discovery** on the local subnet: IP, MAC, vendor (from the IEEE OUI
  registry) and hostname (reverse DNS / mDNS) where available. Randomised
  "private" MAC addresses used by modern phones are recognised and labelled.
- **Port scan** of every device. 44 common ports by default; pass
  `--ports extended` for a bigger list, or your own list/ranges like
  `--ports 22,80,443,8000-8100`.
- **Baseline in SQLite.** The first run is saved as the baseline. Every scan is
  stored, so you also have a history.
- **Change detection.** Later runs flag new devices, missing devices and newly
  opened ports (plus, informationally, closed ports and IP/hostname changes).
  Compare against the baseline (default) or the previous scan.
- **Clean CLI output plus a Markdown report** per run in `reports/`, and an
  optional `--json` mode for scripting.
- **Risky-port hints**: Telnet, unauthenticated Redis/MongoDB, exposed RDP/VNC
  and similar get a one-line note.
- **No sudo needed** for the default mode. An optional ARP-scan mode (faster,
  catches ping-silent devices) uses scapy and needs `sudo`.
- Modular: `scanner`, `storage`, `diff`, `report`, with the network layer fully
  mockable so the tests run anywhere.

## Quick start (macOS, Apple Silicon)

Requirements: Python 3.9 or newer (`python3 --version`). The Xcode Command
Line Tools or Homebrew both provide one. Nothing else needs to be installed
by hand.

```bash
git clone <this-repo-url> netmon
cd netmon
./run.sh
```

That single command creates a virtualenv in `.venv`, installs the
dependencies and runs a scan of your Wi-Fi subnet. The first run becomes the
baseline. Run `./run.sh` again whenever you want to see what changed.

`./run.sh` accepts every `netmon` option, e.g. `./run.sh --ports extended`,
`./run.sh history`, `./run.sh --help`. If you prefer `make`, `make scan` and
`make test` do the same things.

### macOS notes

- **Local Network permission.** On macOS 14+ the first scan may pop up a
  "Terminal would like to find and connect to devices on your local network"
  dialog. Click Allow, otherwise ping and the port scan will find nothing.
- **Subnet detection** uses `route -n get default` and `ifconfig`, both built
  in. If detection fails (VPN active, unusual setup) pass the subnet yourself:
  `./run.sh --subnet 192.168.1.0/24`.
- **Big subnets.** Some routers hand out /16 networks. Scanning 65k addresses
  takes a long time, so netmon refuses anything larger than 1024 addresses
  unless you pass `--max-hosts` or narrow it with `--subnet`.

## What needs sudo

| Operation | Needs sudo? | Why |
|---|---|---|
| Ping sweep (default discovery) | **No** | Uses the system `ping` binary, which macOS lets normal users run. |
| Reading the ARP cache (`arp -a`) for MAC addresses | **No** | Read-only system table. |
| TCP connect port scan | **No** | Ordinary sockets. |
| Reverse DNS / mDNS hostname lookup | **No** | Ordinary resolver calls. |
| ARP scan (`--method arp`) | **Yes** | scapy has to send raw Ethernet frames through BPF, which macOS restricts to root. |
| `netmon oui-update` (download the IEEE vendor list) | **No** | Writes to `~/.netmon/oui.csv`. |

To use the ARP scan:

```bash
./run.sh                    # run once as yourself first, so .venv is owned by you
sudo ./run.sh --method arp  # then the privileged scan
```

`run.sh` is sudo-aware: if `.venv` does not exist yet it creates it as the
invoking user, not as root. With `--method auto` (the default) netmon picks
ARP when it is running as root and scapy is available, and the ping sweep
otherwise.

Why bother with ARP? Some devices (many phones, some IoT gadgets) never answer
ICMP ping but every IPv4 device must answer ARP. The ping sweep partly
compensates by also including devices that are in the OS ARP cache (shown as
"arp-cache" in the report), but the active ARP scan is more thorough.

## Usage

```
netmon                      # same as `netmon scan`
netmon scan [options]       # discover, port-scan, save, diff, report
netmon history              # list saved scans
netmon show <scan-id>       # print the devices from a saved scan
netmon baseline             # show the baseline
netmon baseline --use 7     # promote scan #7 to be the baseline
netmon baseline --clear     # forget the baseline; the next scan becomes it
netmon oui-update           # download the full IEEE vendor registry (~50k entries)
```

Useful `scan` options (see `netmon scan --help` for all of them):

| Option | Default | Meaning |
|---|---|---|
| `--subnet CIDR` | auto-detect | Network to scan, e.g. `192.168.1.0/24` |
| `--interface NAME` | default route | Interface to auto-detect from, e.g. `en0` |
| `--ports SPEC` | `common` | `common`, `extended`, or `22,80,443,8000-8100` |
| `--method auto\|ping\|arp` | `auto` | Discovery back-end |
| `--compare baseline\|previous` | `baseline` | What to diff against |
| `--set-baseline` | off | Make this scan the new baseline |
| `--fail-on-change` | off | Exit with status 2 if new/missing devices or new ports were found |
| `--json` | off | Print the scan and diff as JSON |
| `--no-report` | off | Skip writing the Markdown report |
| `--no-hostnames` | off | Skip reverse-DNS lookups (faster) |
| `--db PATH` | `netmon.db` | SQLite database location |
| `--reports-dir DIR` | `reports/` | Where Markdown reports go |
| `--ping-timeout`, `--port-timeout`, `--workers` | 1.0s, 0.5s, 64 | Tuning knobs |

Exit codes: `0` success, `1` error, `2` changes detected (only with
`--fail-on-change`), which makes it easy to run from cron or launchd:

```bash
# every night at 03:00, keep the report, notify only on change
0 3 * * * cd /path/to/netmon && ./run.sh -q --fail-on-change || osascript -e 'display notification "Network changed - check reports/" with title "netmon"'
```

## Example output

### First run (baseline)

```
$ ./run.sh
Home Network Monitor - scan #1 of 192.168.1.0/24
2026-09-26 14:03:11 -> 14:03:28 (17.4s) | discovery: ping | 44 ports probed per host

Devices (6)
IP            MAC                Vendor                     Hostname                  Open ports
------------  -----------------  -------------------------  ------------------------  -----------------------------------
192.168.1.1   a4:2b:8c:01:34:56  Netgear                    router.local              53 (dns), 80 (http), 443 (https)
192.168.1.10  3c:22:fb:aa:bb:cc  Apple                      Talans-MacBook-Pro.local  5000 (upnp/airplay), 7000 (airplay)
192.168.1.20  b8:27:eb:12:34:56  Raspberry Pi Foundation    pi.local                  22 (ssh), 80 (http)
192.168.1.30  5c:aa:fd:11:22:33  Sonos                      -                         -
192.168.1.40  da:12:34:56:78:9a  Private (randomized MAC)   -                         62078 (iphone-sync)
192.168.1.60  18:fe:34:9a:bc:de  Espressif (ESP8266/ESP32)  -                         80 (http), 1883 (mqtt)

Saved as BASELINE. Future scans will be compared against this one.

Worth a look
  * 192.168.1.60 (Espressif (ESP8266/ESP32)) has 1883 (mqtt) open: MQTT broker - check it requires authentication

Report written to reports/2026-09-26_140311.md
```

Progress messages ("Pinging 254 addresses ...", "Scanning 44 ports on 6
hosts ...") go to stderr so the table above stays clean when piped to a file.
`-q` silences them.

### Scan history

```
$ ./run.sh history
ID  Started              Subnet          Method  Devices  Baseline
--  -------------------  --------------  ------  -------  --------
2   2026-10-03 14:03:11  192.168.1.0/24  ping    6
1   2026-09-26 14:03:11  192.168.1.0/24  ping    6        yes
```

### Markdown report (`reports/2026-10-03_140311.md`)

```markdown
# Network scan report #2 - 2026-10-03 14:03:11

| Field | Value |
|---|---|
| Subnet | 192.168.1.0/24 |
| Discovery method | ping |
| Started | 2026-10-03 14:03:11 |
| Finished | 2026-10-03 14:03:28 |
| Duration | 17.4s |
| Devices found | 6 |
| Ports probed per host | 44 |
| Compared against | baseline from 2026-09-26 14:03:11 |

## Summary

- **1** new device(s)
- **1** missing device(s)
- **1** newly opened port(s)
- 3 device(s) unchanged

## Changes vs baseline

### New devices

| IP | MAC | Vendor | Hostname | Open ports |
|---|---|---|---|---|
| 192.168.1.50 | f0:d2:f1:44:55:66 | Amazon Technologies | - | 8080 (http-proxy) |

### Missing devices

| IP | MAC | Vendor | Hostname | Ports (last seen) |
|---|---|---|---|---|
| 192.168.1.30 | 5c:aa:fd:11:22:33 | Sonos | - | - |

### Port changes

| IP | Device | Newly opened | Closed |
|---|---|---|---|
| 192.168.1.20 | pi.local | 5900 (vnc) | - |

### Address / hostname changes

| Device (MAC) | IP | Hostname |
|---|---|---|
| da:12:34:56:78:9a | 192.168.1.40 -> 192.168.1.41 | - |

## All devices

| IP | MAC | Vendor | Hostname | Open ports | Seen via |
|---|---|---|---|---|---|
| 192.168.1.1 | a4:2b:8c:01:34:56 | Netgear | router.local | 53 (dns), 80 (http), 443 (https) | ping |
| 192.168.1.10 | 3c:22:fb:aa:bb:cc | Apple | Talans-MacBook-Pro.local | 5000 (upnp/airplay), 7000 (airplay) | self |
| 192.168.1.20 | b8:27:eb:12:34:56 | Raspberry Pi Foundation | pi.local | 22 (ssh), 80 (http), 5900 (vnc) | ping |
| 192.168.1.41 | da:12:34:56:78:9a | Private (randomized MAC) | - | 62078 (iphone-sync) | arp-cache |
| 192.168.1.50 | f0:d2:f1:44:55:66 | Amazon Technologies | - | 8080 (http-proxy) | ping |
| 192.168.1.60 | 18:fe:34:9a:bc:de | Espressif (ESP8266/ESP32) | - | 80 (http), 1883 (mqtt) | ping |

## Worth a look

- 192.168.1.20 (pi.local) has 5900 (vnc) open: VNC remote control - check it needs a password
- 192.168.1.60 (Espressif (ESP8266/ESP32)) has 1883 (mqtt) open: MQTT broker - check it requires authentication
```

## How it works

```
netmon/
  cli.py       argparse front-end; wires the pieces below together
  netinfo.py   finds the default interface, local IP, netmask and MAC (route/ifconfig/ip)
  scanner.py   device discovery (ping sweep + ARP cache, or scapy ARP), hostname lookup, TCP port scan
  vendors.py   MAC -> vendor via IEEE OUI prefixes; detects randomised MACs
  storage.py   SQLite persistence (scans, devices, open_ports) and baseline management
  diff.py      pure comparison of two scans -> new / missing / changed devices
  report.py    console rendering, Markdown report, JSON output
  models.py    Device and ScanResult dataclasses
  data/oui.txt curated OUI table (~750 prefixes) so the tool works offline
tests/         pytest suite; every network call is replaced by canned data
run.sh         one-command launcher (venv + deps + run)
```

A scan runs in four steps:

1. **Discover.** Ping every address in the subnet concurrently, then read the
   OS ARP cache (`arp -a`) to get MAC addresses. Hosts that did not answer
   ping but are in the ARP cache are kept too. This machine is always added
   from its interface details. With `--method arp`, scapy broadcasts ARP
   requests instead.
2. **Enrich.** Look up the vendor from the MAC's first three bytes and resolve
   hostnames via reverse DNS (on macOS this also returns the Bonjour `.local`
   name of many devices).
3. **Port scan.** A TCP `connect()` probe for every (host, port) pair through
   one shared thread pool.
4. **Store, diff, report.** Save the run to SQLite, compare it to the baseline
   by MAC address (falling back to IP when no MAC is known), print the result
   and write `reports/<timestamp>.md`.

Devices are matched across scans by **MAC address**, so a phone that gets a
new DHCP lease shows up as "ip changed", not as a new device. A phone whose
privacy setting rotates its MAC per network will, by design, look like a
different device each time it rotates.

### Vendor database

`netmon/data/oui.txt` ships with a curated subset of the IEEE registry
covering common consumer vendors (Apple, Google, Amazon, Samsung, Raspberry
Pi, TP-Link, Netgear, Sonos, Espressif, ...). For full coverage run:

```bash
./run.sh oui-update     # downloads oui.csv from standards-oui.ieee.org to ~/.netmon/
```

The downloaded file takes precedence over the bundled list.

## Running the tests

The suite mocks every network call (ping, ARP cache, sockets, DNS), so it
runs anywhere, including CI containers with no network at all.

```bash
make test
# or
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Expect something like `128 passed in 0.5s`. The tests cover the parsers with
real macOS and Linux command output, the SQLite round-trip, every kind of
diff, the report renderers and the CLI end to end.

## Limitations

- TCP only. UDP services (DNS on 53/udp, mDNS, SSDP) are not probed.
- Ping-silent devices are found only via the ARP cache or `--method arp`.
  ARP-cache entries can be a few minutes stale.
- The ping sweep on a /24 takes roughly 5 to 20 seconds depending on how many
  addresses are silent. Larger subnets scale linearly.
- IPv4 only.
- Hostnames depend on what your router and the devices advertise; many IoT
  gadgets have none.

## Dependencies

- Python 3.9+ standard library for everything in the default mode.
- [`scapy`](https://scapy.net/) (in `requirements.txt`) for the optional
  `--method arp` mode. It installs cleanly on Apple Silicon and uses the
  libpcap that ships with macOS.
- `pytest` for the test-suite (`requirements-dev.txt`).
