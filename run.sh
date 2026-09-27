#!/usr/bin/env bash
# One-command launcher: creates a virtualenv on first run, installs the
# dependencies, then runs netmon with whatever arguments you pass.
#
#   ./run.sh                       # scan (ping sweep, no sudo needed)
#   ./run.sh --ports extended      # any `netmon scan` option works
#   sudo ./run.sh --method arp     # ARP scan (needs root for raw sockets)
#   ./run.sh history               # other sub-commands
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
VENV=".venv"

# When launched through sudo, create the venv as the real user so the
# directory is not owned by root.
as_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
        sudo -u "$SUDO_USER" "$@"
    else
        "$@"
    fi
}

if [ ! -x "$VENV/bin/python" ]; then
    echo "Creating virtualenv in $VENV ..." >&2
    as_user "$PYTHON" -m venv "$VENV"
fi

if [ ! -f "$VENV/.deps-installed" ] || [ requirements.txt -nt "$VENV/.deps-installed" ]; then
    echo "Installing dependencies ..." >&2
    as_user "$VENV/bin/python" -m pip install --quiet --upgrade pip
    as_user "$VENV/bin/python" -m pip install --quiet -r requirements.txt
    as_user touch "$VENV/.deps-installed"
fi

exec "$VENV/bin/python" -m netmon "$@"
