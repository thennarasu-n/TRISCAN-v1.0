#!/usr/bin/env bash
# TriScan installer for Kali Linux (and other Debian-based distros).
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Checking system packages (python3-venv, python3-pip)…"
if ! python3 -c "import venv, ensurepip" 2>/dev/null; then
    sudo apt-get update -y && sudo apt-get install -y python3-venv python3-pip
fi

echo "[*] Creating virtual environment (.venv)…"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip >/dev/null
pip install -r requirements.txt

echo "[*] Creating the Django database (users + scan history)…"
python manage.py makemigrations history --noinput
python manage.py migrate --noinput

echo "[*] Training the Random Forest models…"
python triscan.py --train

chmod +x run.sh triscan.py manage.py
echo
echo "[+] Done.  Start TriScan with:   ./run.sh        (full system audit: sudo ./run.sh)"
