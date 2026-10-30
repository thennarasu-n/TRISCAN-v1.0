# TriScan

Command-line security scanner for **Kali Linux** with three scanners, a login gate, scan history and Random Forest (scikit-learn) detection.

| Scanner | What it does |
|---|---|
| **Network** | Scan an IP: **outside India → CRITICAL**, **India → SUSPICIOUS**, **local/private → MEDIUM**. Shows live geolocation (country, city, lat/lon, ISP, hosting/proxy), reverse DNS, common-port scan and an ML threat score. A **live monitor** classifies every remote connection of your device in real time. |
| **Website** | Give a URL: crawls the whole site (same host, default 30 pages) and reports bugs and malware indicators, with a final **SAFE / NOT SAFE** verdict and a live ML risk meter while it crawls. |
| **System** | Scans the whole device: CPU, RAM, swap, disk, **battery %**, critical folders/files (permissions, owner, size), SUID/world-writable files, executables in `/tmp`, suspicious processes, risky open ports, then an ML verdict (HEALTHY / WARNING / CRITICAL). A live dashboard is included. |

Users and scan history are stored in a **Django database** (SQLite, `data/triscan.sqlite3`). Passwords are stored **hashed** (PBKDF2-SHA256), never in plain text.

## Install (Kali)

```bash
cd triscan
./install.sh        # venv + dependencies + database + trains the ML models
./run.sh            # start TriScan  (use `sudo ./run.sh` for a full system audit)
```

First launch asks you to create the first account; afterwards you log in with username + password (3 attempts). Other users can register from the login screen.

`python3 triscan.py --train` retrains the models at any time.

## Project layout

```
triscan.py            CLI menu + report rendering (entry point)
core/ui.py            ANSI command-line UI (tables, bars, spinner)
core/auth.py          login / register (Django auth)
core/db.py            Django bootstrap + history helpers
core/ml.py            Random Forest detectors (network, website, system)
scanners/network.py   geolocation rule, port scan, live connection monitor
scanners/website.py   crawler + passive vulnerability / malware checks
scanners/system.py    resource, folder, filesystem and process audit
history/models.py     ScanRecord, LoginEvent
config/settings.py    Django settings (SQLite)
install.sh run.sh     Kali install and launch scripts
```

## How the ML works

Three scikit-learn `RandomForestClassifier`s (200 trees) turn scan features into a class and a 0-100 threat score, and an occlusion test lists the top factors that raised the score.

* **Important:** no labelled public dataset ships with TriScan. On first run the models train on a **synthetic dataset** that encodes common security heuristics, which gives a working baseline but is *not* proof of real-world accuracy. For real accuracy, add your own labelled data as `data/network_dataset.csv`, `data/website_dataset.csv`, `data/system_dataset.csv` (columns = feature names in `core/ml.py` plus a `label` column) and run `python3 triscan.py --train`.
* Website verdicts also apply hard rules: a crypto-miner signature, or a hidden iframe together with obfuscated JavaScript, is always classified MALICIOUS.

## Notes and limits

* **Geolocation** uses the free `ip-api.com` service (needs internet; ~45 requests/min). If it is unreachable, public IPs are rated SUSPICIOUS with location "Unknown".
* **Website scanner is passive**: it fetches pages and a handful of well-known sensitive paths (`/.env`, `/.git/HEAD`, …). It sends no attack payloads and is not a replacement for a full pentest or antivirus. It detects indicators (hidden iframes, obfuscated JS, miner scripts, executable downloads), not every possible malware.
* **System scan** is read-only. Run with `sudo` to read `/root`, `/etc/shadow` permissions and all process/port owners. The default scan walks `/` with a 2-minute limit.
* Scan only networks, hosts and websites you own or are authorised to test.
