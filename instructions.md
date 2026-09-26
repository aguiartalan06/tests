Build a home network monitor in Python for scanning my own home Wi-Fi network (I own the network and every device on it). This is a cybersecurity portfolio project.

Features:
- Discover devices on the local subnet (IP, MAC, vendor, hostname if available)
- Scan each device for open ports (common ports by default, configurable)
- Save the first run as a baseline in SQLite
- On later runs, flag new devices, missing devices, and newly opened ports
- Clean CLI output plus a markdown report per run

Requirements:
- Runs on macOS (Apple Silicon); document anything that needs sudo
- requirements.txt and a README with setup, usage, and example output
- You're in a cloud VM that can't reach my home network, so write tests using mocked scan data and make sure they pass
- Keep it modular: scanner, storage, diff, report

Done = tests pass, README is complete, and I can clone it and run it on my Mac with one command.
