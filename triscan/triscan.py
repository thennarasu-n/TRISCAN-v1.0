#!/usr/bin/env python3
"""TriScan — Network · Website · System security scanner (command-line UI).

Usage:
    python3 triscan.py            # login, then interactive menu
    python3 triscan.py --train    # (re)train the Random Forest models and exit
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import ui  # noqa: E402

VERSION = "1.0.0"
LEVEL_ORDER = ["INFO", "LOW", "MEDIUM", "SUSPICIOUS", "HIGH", "CRITICAL"]


# =============================================================== NETWORK
def render_ip(r: dict):
    geo = r["geo"]
    ui.title(f"Network scan · {r['ip']}")
    ui.kv([
        ("Risk level", ui.level(r["level"]) + "  " + ui.c(r["reason"], "dim")),
        ("Location", r["location"]),
        ("Coordinates", f"{geo.get('lat')}, {geo.get('lon')}" if geo.get("lat") is not None else "-"),
        ("ISP / Org", f"{geo.get('isp', '-')} / {geo.get('org', '-')}" if geo else "-"),
        ("AS", geo.get("as", "-") if geo else "-"),
        ("Hosting / proxy", "yes" if geo.get("hosting") or geo.get("proxy") else "no"),
        ("Reverse DNS", r["reverse_dns"] or "-"),
    ])
    v = r["ml"]
    print()
    ui.kv([("ML threat score", ui.score_bar(v["score"])),
           ("ML verdict", ui.level(v["label"]) + ui.c(f"  p={v['proba']}", "dim"))])
    for f, val, d in v["drivers"]:
        print("    " + ui.c(f"▲ {f} = {val:g}  (+{d} threat)", "byellow"))
    if r["open_ports"]:
        print()
        ui.table(["Port", "Service", "Risk"],
                 [[p["port"], p["service"], ui.level("HIGH") if p["risky"] else ui.c("ok", "dim")]
                  for p in r["open_ports"]])
    else:
        print("\n  " + ui.c("No common TCP ports answered.", "dim"))


def network_menu(user):
    from core import db
    from scanners import network
    while True:
        ui.title("Network scanner")
        print("  1) Scan an IP address (location risk + ports + ML)")
        print("  2) Live connection monitor (this device, real time)")
        print("  0) Back")
        ch = ui.ask("Choose", "1")
        if ch == "0":
            return
        if ch == "1":
            raw = ui.ask("IP address")
            try:
                addr = ipaddress.ip_address(raw.strip().split("%")[0])
            except ValueError:
                ui.err("That is not a valid IP address.")
                continue
            do_ports = True
            if addr.is_global:
                do_ports = ui.confirm("Run a TCP port probe on this public host? (only do this if you are authorised)")
            with ui.Spinner(f"Locating and analysing {addr}…"):
                r = network.scan_ip(str(addr), ports=do_ports)
            render_ip(r)
            rec = db.save_scan(user, "network", r["ip"], r["level"], r["ml"]["score"],
                               f"{r['level']} · {r['location']} · {len(r['open_ports'])} open ports", r)
            ui.ok(f"Saved to history as #{rec.pk}")
            ui.pause()
        elif ch == "2":
            live_monitor(user)


def live_monitor(user):
    from core import db
    from scanners import network
    ui.info("Live monitor started — press Ctrl+C to stop. (Run with sudo to see all process names.)")
    time.sleep(1)
    worst, seen_critical, snapshots = "MEDIUM", {}, 0
    try:
        for rows in network.monitor(interval=4):
            snapshots += 1
            ui.clear()
            ui.banner("Live connection monitor")
            counts = {l: sum(1 for r in rows if r["level"] == l) for l in ("CRITICAL", "SUSPICIOUS", "MEDIUM")}
            print(f"  {ui.level('CRITICAL')} {counts['CRITICAL']}   {ui.level('SUSPICIOUS')} {counts['SUSPICIOUS']}   "
                  f"{ui.level('MEDIUM')} {counts['MEDIUM']}   {ui.c('· refresh 4s · Ctrl+C to stop', 'dim')}\n")
            body = [[ui.level(r["level"]), r["ip"], ui.trunc(r["location"], 28), ui.trunc(",".join(r["procs"]) or "-", 14),
                     ",".join(map(str, r["ports"][:3])), r["count"], f"{r['ml']['score']:.0f}"] for r in rows[:18]]
            if body:
                ui.table(["Level", "Remote IP", "Location", "Process", "Port", "Conn", "ML"], body)
            else:
                print("  " + ui.c("No active remote connections right now.", "dim"))
            for r in rows:
                if r["level"] == "CRITICAL":
                    seen_critical[r["ip"]] = r["location"]
                if network.LEVEL_RANK[r["level"]] > network.LEVEL_RANK[worst]:
                    worst = r["level"]
    except KeyboardInterrupt:
        pass
    print()
    if snapshots:
        details = {"snapshots": snapshots, "critical_hosts": seen_critical}
        rec = db.save_scan(user, "network", "live connections", worst, 0.0,
                           f"Live monitor · {snapshots} snapshots · {len(seen_critical)} critical host(s)", details)
        ui.ok(f"Live session saved to history as #{rec.pk}")
    ui.pause()


# =============================================================== WEBSITE
SEV_STYLE = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def website_menu(user):
    from core import db
    from scanners.website import WebsiteScanner
    ui.title("Website scanner")
    url = ui.ask("Website URL or domain")
    if not url:
        return
    try:
        pages = int(ui.ask("Max pages to crawl", "30"))
    except ValueError:
        pages = 30
    if not ui.confirm("Do you own this site or have permission to test it?", default=True):
        ui.warn("Scan cancelled.")
        return

    state = {"score": 0.0}

    def on_event(kind, data):
        if kind == "status":
            ui.live(ui.c("⠿ ", "bcyan") + ui.trunc(data, 70) + ui.c(f"   ML risk {state['score']:.0f}/100", "dim"))
        elif kind == "progress":
            state["score"] = data["score"]
            ui.live(ui.c("⠿ ", "bcyan") + f"pages {data['pages']} · queued {data['queued']} · findings {data['findings']}"
                    + "   ML risk " + ui.score_bar(data["score"], 12))
        elif kind == "finding" and data["severity"] in ("critical", "high"):
            ui.live_done()
            print("  " + ui.level(SEV_STYLE[data["severity"]]) + " " + ui.trunc(data["title"], 70)
                  + ui.c("  " + ui.trunc(data["url"], 40), "dim"))

    try:
        scanner = WebsiteScanner(url, max_pages=pages, on_event=on_event)
    except ValueError as e:
        ui.err(str(e))
        return
    t0 = time.time()
    try:
        rep = scanner.run()
    except KeyboardInterrupt:
        ui.live_done()
        ui.warn("Scan interrupted — showing partial results.")
        rep = scanner.report()
    ui.live_done()
    render_site(rep, time.time() - t0)
    status = "SAFE" if rep["safe"] else "NOT SAFE"
    rec = db.save_scan(user, "website", rep["url"], rep["verdict"], rep["ml"]["score"],
                       f"{status} · {rep['pages_scanned']} pages · {len(rep['findings'])} findings · "
                       f"{rep['malware_indicators']} malware indicators", rep)
    ui.ok(f"Saved to history as #{rec.pk}")
    ui.pause()


def render_site(rep: dict, secs: float):
    ui.title(f"Website report · {rep['url']}")
    verdict = "SAFE" if rep["safe"] else "NOT SAFE"
    sc = rep["severity_counts"]
    lines = [
        f"Verdict      {ui.level(verdict)}   classified {ui.level(rep['verdict'])}  ·  Random Forest says {rep['ml']['label']}",
        f"ML risk      {ui.score_bar(rep['ml']['score'])}",
        f"Pages        {rep['pages_scanned']} scanned in {secs:.1f}s",
        f"Severity     critical {sc.get('critical', 0)} · high {sc.get('high', 0)} · medium {sc.get('medium', 0)} · low {sc.get('low', 0)}",
        f"Malware      {rep['malware_indicators']} indicator(s)",
    ]
    ui.box(lines, "RESULT", "bred" if not rep["safe"] else "bgreen")
    for f, val, d in rep["ml"]["drivers"]:
        print("    " + ui.c(f"▲ {f} = {val:g}  (+{d} threat)", "byellow"))
    if rep["findings"]:
        print()
        rows = [[ui.level(SEV_STYLE[f["severity"]]), f["category"], ui.trunc(f["title"], 52), ui.trunc(f["url"], 38)]
                for f in rep["findings"][:40]]
        ui.table(["Severity", "Type", "Finding", "Where"], rows)
        if len(rep["findings"]) > 40:
            print(ui.c(f"  … {len(rep['findings']) - 40} more saved in history", "dim"))
    else:
        ui.ok("No issues found.")
    if not rep["safe"]:
        print()
        ui.warn("This website is NOT safe: fix the CRITICAL/HIGH items first (exposed files, malware indicators, TLS).")


# =============================================================== SYSTEM
def system_menu(user):
    from core import db
    from scanners import system
    while True:
        ui.title("System scanner")
        print("  1) Full device scan (resources, critical folders, files, processes, ports)")
        print("  2) Live resource dashboard (CPU / RAM / battery + ML status)")
        print("  0) Back")
        ch = ui.ask("Choose", "1")
        if ch == "0":
            return
        if ch == "2":
            live_dashboard()
            continue
        if ch != "1":
            continue
        root = ui.ask("Folder to scan ('/' = entire device)", "/")
        if not os.path.isdir(root):
            ui.err("That folder does not exist.")
            continue
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            ui.warn("Not running as root — some folders will be unreadable. For a full audit use: sudo ./run.sh")
        t0 = time.time()
        with ui.Spinner("Scanning…") as sp:
            def prog(res):
                sp.update(f"Scanning {res['files_checked']:,} files · {len(res['suid_unusual'])} SUID · "
                          f"{len(res['world_writable'])} world-writable · {len(res['tmp_executables'])} tmp executables")
            rep = system.full_scan(root, time_limit=120, progress=prog)
        render_system(rep, time.time() - t0)
        v = rep["ml"]
        rec = db.save_scan(user, "system", root, v["label"], v["score"],
                           f"{v['label']} · CPU {rep['metrics']['cpu_percent']}% · RAM {rep['metrics']['ram_percent']}% · "
                           f"{len(rep['recommendations'])} issue(s)", rep)
        ui.ok(f"Saved to history as #{rec.pk}")
        ui.pause()


def render_system(rep: dict, secs: float):
    m, fs = rep["metrics"], rep["filesystem"]
    ui.title("System report")
    bat = m["battery"]
    ui.kv([
        ("CPU", f"{ui.bar(m['cpu_percent'])}  {m['cpu_cores']} cores · load {m['load_avg']}"),
        ("RAM", f"{ui.bar(m['ram_percent'])}  {m['ram_used_gb']}/{m['ram_total_gb']} GB"),
        ("Swap", ui.bar(m["swap_percent"])),
        ("Disk /", f"{ui.bar(m['disk_percent'])}  {m['disk_used_gb']}/{m['disk_total_gb']} GB"),
        ("Battery", (f"{ui.bar(bat['percent'], invert=True)}  {'charging / plugged in' if bat['plugged'] else 'on battery'}"
                     + (f" · {bat['minutes_left']} min left" if bat['minutes_left'] else "")) if bat
         else ui.c("no battery detected (desktop / VM)", "dim")),
        ("Temperature", f"{m['temperature_c']} °C" if m["temperature_c"] else ui.c("n/a", "dim")),
        ("Uptime", f"{m['uptime_h']} h"),
    ])
    ui.title("Critical folders & files")
    ui.table(["Path", "Purpose", "Mode", "Owner", "Size", "Status"],
             [[f["path"], ui.trunc(f["desc"], 22), f["mode"], f["owner"], f["size"], ui.level(f["status"])]
              for f in rep["folders"]])
    for f in rep["folders"]:
        if f["note"]:
            print("  " + ui.c("• ", "byellow") + f"{f['path']}: {f['note']}")

    ui.title("Filesystem audit")
    ui.kv([
        ("Scanned", f"{fs['files_checked']:,} files in {fs['dirs_checked']:,} folders ({fs['seconds']}s)"
                    + (ui.c("  [time/size limit reached]", "byellow") if fs["truncated"] else "")),
        ("Unexpected SUID/SGID", len(fs["suid_unusual"])),
        ("World-writable files", len(fs["world_writable"])),
        ("Executables in /tmp", len(fs["tmp_executables"])),
    ])
    for label, key in (("SUID/SGID", "suid_unusual"), ("World-writable", "world_writable"), ("Temp executable", "tmp_executables")):
        for p in fs[key][:4]:
            print("    " + ui.c(f"{label}: ", "byellow") + p)

    pr = rep["processes"]
    ui.title(f"Processes ({pr['count']})")
    ui.table(["Top CPU", "PID", "CPU %", "", "Top memory", "PID", "Mem %"],
             [[ui.trunc(a.get("name") or "?", 18), a["pid"], f"{a.get('cpu_percent') or 0:.1f}", "",
               ui.trunc(b.get("name") or "?", 18), b["pid"], f"{b.get('memory_percent') or 0:.1f}"]
              for a, b in zip(pr["top_cpu"], pr["top_mem"])])
    for s in pr["suspicious"]:
        print("  " + ui.level("CRITICAL") + f" {s['name']} (pid {s['pid']}, {s['user']}): {s['why']}")
    risky = [l for l in rep["listeners"] if l["risky"]]
    print(f"\n  Listening ports: {len(rep['listeners'])}   risky & exposed: {len(risky)}")
    for l in risky:
        print("  " + ui.level("HIGH") + f" {l['service']} on port {l['port']} ({l['proc']}) open to all interfaces")

    v = rep["ml"]
    ui.title("ML verdict")
    ui.box([f"System state  {ui.level(v['label'])}", f"Threat score  {ui.score_bar(v['score'])}",
            f"Class probs   {v['proba']}"], "RANDOM FOREST",
           "bgreen" if v["label"] == "HEALTHY" else "byellow" if v["label"] == "WARNING" else "bred")
    for f, val, d in v["drivers"]:
        print("    " + ui.c(f"▲ {f} = {val:g}  (+{d} threat)", "byellow"))
    if rep["recommendations"]:
        ui.title("What to fix")
        for r in rep["recommendations"][:15]:
            print("  " + ui.c("➜ ", "bcyan") + r)
    print(ui.c(f"\n  Finished in {secs:.1f}s", "dim"))


def live_dashboard():
    from scanners import system
    ui.info("Live dashboard — press Ctrl+C to stop.")
    time.sleep(0.8)
    try:
        while True:
            q = system.quick_status()
            m, v = q["metrics"], q["ml"]
            ui.clear()
            ui.banner("Live system dashboard")
            bat = m["battery"]
            ui.kv([
                ("CPU", ui.bar(m["cpu_percent"])), ("RAM", ui.bar(m["ram_percent"])),
                ("Swap", ui.bar(m["swap_percent"])), ("Disk /", ui.bar(m["disk_percent"])),
                ("Battery", (ui.bar(bat["percent"], invert=True) + ("  ⚡ charging" if bat["plugged"] else "  on battery"))
                 if bat else ui.c("none", "dim")),
                ("ML status", ui.level(v["label"]) + "  " + ui.score_bar(v["score"], 16)),
            ])
            time.sleep(1.5)
    except KeyboardInterrupt:
        print()


# =============================================================== HISTORY
def history_menu(user):
    from core import db
    while True:
        ui.title("Scan history")
        rows = db.list_scans(user, 25)
        if not rows:
            ui.info("No scans yet.")
            ui.pause()
            return
        ui.table(["#", "When", "Type", "Target", "Risk", "ML", "Summary"],
                 [[r.pk, r.created_at.astimezone().strftime("%d %b %H:%M"), r.scan_type, ui.trunc(r.target, 26),
                   ui.level(r.risk_level), f"{r.ml_score:.0f}", ui.trunc(r.summary, 44)] for r in rows])
        ch = ui.ask("Enter a scan # to view, 'd #' to delete, or Enter to go back")
        if not ch:
            return
        if ch.lower().startswith("d "):
            try:
                ui.ok("Deleted.") if db.delete_scan(user, int(ch[2:])) else ui.err("Not found.")
            except ValueError:
                ui.err("Use: d <number>")
            continue
        try:
            rec = db.get_scan(user, int(ch))
        except ValueError:
            rec = None
        if not rec:
            ui.err("Scan not found.")
            continue
        show_record(rec)
        ui.pause()


def show_record(rec):
    ui.title(f"Scan #{rec.pk} · {rec.scan_type} · {rec.target}")
    ui.kv([("When", rec.created_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")),
           ("Risk", ui.level(rec.risk_level)), ("ML score", ui.score_bar(rec.ml_score)), ("Summary", rec.summary)])
    d = rec.details or {}
    if rec.scan_type == "website" and d.get("findings"):
        print()
        ui.table(["Severity", "Finding", "Where"],
                 [[ui.level(SEV_STYLE[f["severity"]]), ui.trunc(f["title"], 56), ui.trunc(f["url"], 40)] for f in d["findings"][:40]])
    elif rec.scan_type == "network" and d.get("open_ports") is not None:
        ui.kv([("Location", d.get("location", "-")), ("Reverse DNS", d.get("reverse_dns") or "-"),
               ("Open ports", ", ".join(str(p["port"]) for p in d["open_ports"]) or "none")])
    elif rec.scan_type == "system":
        for r in d.get("recommendations", [])[:15]:
            print("  " + ui.c("➜ ", "bcyan") + r)


# =============================================================== MODELS
def train_models():
    from core import ml
    ui.title("Training Random Forest models")
    for k, d in ml.DETECTORS.items():
        with ui.Spinner(f"Training {k} detector…"):
            m = d.train()
        ui.ok(f"{k:8s} accuracy {m['accuracy']:.3f} · macro-F1 {m['macro_f1']:.3f} · {m['samples']} samples ({m['source']})")


# =============================================================== MAIN
def main_menu(user):
    from core import ml
    while True:
        ui.clear()
        ui.banner()
        print(f"  Logged in as {ui.c(user.username, 'bgreen', 'bold')}\n")
        print(f"  {ui.c('1', 'bcyan')}) Network scanner   {ui.c('IP location risk · ports · live connections', 'dim')}")
        print(f"  {ui.c('2', 'bcyan')}) Website scanner   {ui.c('crawl · bugs · malware · safe / not safe', 'dim')}")
        print(f"  {ui.c('3', 'bcyan')}) System scanner    {ui.c('critical folders · CPU/RAM · battery', 'dim')}")
        print(f"  {ui.c('4', 'bcyan')}) Scan history")
        print(f"  {ui.c('5', 'bcyan')}) Retrain ML models")
        print(f"  {ui.c('0', 'bcyan')}) Logout / exit\n")
        ch = ui.ask("Select", "1")
        try:
            if ch == "1":
                network_menu(user)
            elif ch == "2":
                website_menu(user)
            elif ch == "3":
                system_menu(user)
            elif ch == "4":
                history_menu(user)
            elif ch == "5":
                train_models()
                ui.pause()
            elif ch == "0":
                return
        except KeyboardInterrupt:
            print()
        except Exception as e:  # keep the menu alive on unexpected scanner errors
            ui.err(f"{type(e).__name__}: {e}")
            ui.pause()


def main():
    ap = argparse.ArgumentParser(prog="triscan", description="TriScan security scanner")
    ap.add_argument("--train", action="store_true", help="train the ML models and exit")
    ap.add_argument("--version", action="version", version=f"TriScan {VERSION}")
    args = ap.parse_args()

    if args.train:
        train_models()
        return 0

    from core import db, auth, ml
    try:
        db.init()
        user = auth.gate()
        if not user:
            ui.info("Bye.")
            return 1
        with ui.Spinner("Loading ML models…"):
            for k in ml.DETECTORS:
                ml.get(k)
        main_menu(user)
    except KeyboardInterrupt:
        print()
    ui.info("Logged out. Stay safe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
