#!/usr/bin/env bash
# Launch TriScan inside its virtualenv. Use `sudo ./run.sh` for a full system audit.
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    echo "[x] Not installed yet. Run ./install.sh first."
    exit 1
fi

# If started with sudo, give the data folder back to the real user on exit
# so the database stays usable when you later run without sudo.
if [ -n "${SUDO_USER:-}" ]; then
    trap 'chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" data history/migrations 2>/dev/null' EXIT
fi

.venv/bin/python triscan.py "$@"
