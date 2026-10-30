"""System scanner (Linux / Kali): resources, critical folders, filesystem and process audit.

Everything is read-only. A Random Forest turns the collected metrics into a
HEALTHY / WARNING / CRITICAL verdict with the main risk drivers.
"""
from __future__ import annotations

import os
import stat
import time

import psutil

from core import ml

# path, maximum permission bits it should have, expected owner uid (None = don't check), description
CRITICAL_PATHS = [
    ("/etc", 0o755, 0, "System configuration"),
    ("/etc/passwd", 0o644, 0, "User accounts"),
    ("/etc/shadow", 0o640, 0, "Password hashes"),
    ("/etc/sudoers", 0o440, 0, "Sudo privileges"),
    ("/etc/ssh/sshd_config", 0o644, 0, "SSH server config"),
    ("/etc/crontab", 0o644, 0, "System cron jobs"),
    ("/boot", 0o755, 0, "Kernel & bootloader"),
    ("/root", 0o750, 0, "Root home"),
    ("/usr/bin", 0o755, 0, "System binaries"),
    ("/usr/sbin", 0o755, 0, "Admin binaries"),
    ("/var/log", 0o755, 0, "System logs"),
    ("/home", 0o755, 0, "User homes"),
    ("/opt", 0o755, 0, "Optional software"),
    ("/var/www", 0o755, None, "Web root"),
    ("/tmp", 0o1777, 0, "Temp files"),
    ("/var/tmp", 0o1777, 0, "Persistent temp"),
]

KNOWN_SUID = {
    "su", "sudo", "sudoedit", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "mount", "umount",
    "ping", "ping6", "pkexec", "fusermount", "fusermount3", "ssh-keysign", "chage", "expiry",
    "unix_chkpwd", "write", "wall", "crontab", "at", "polkit-agent-helper-1", "mtr-packet",
    "dbus-daemon-launch-helper", "Xorg.wrap", "ntfs-3g", "pppd", "snap-confine", "bwrap",
    "traceroute6.iputils", "mount.nfs", "mount.cifs", "umount.nfs", "vmware-user-suid-wrapper",
    "chrome-sandbox", "staprun", "ssh-agent", "locate", "plocate", "mlocate", "unix2_chkpwd",
    "pam_extrausers_chkpwd", "lppasswd", "userhelper", "Xorg", "doas", "opensudo", "sudo-rs", "su-rs",
}
RISKY_LISTEN = {21: "FTP", 23: "Telnet", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
                1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 6379: "Redis",
                9200: "Elasticsearch", 27017: "MongoDB"}
MINER_NAMES = ("xmrig", "minerd", "cpuminer", "kdevtmpfsi", "kinsing", "ethminer", "cgminer", "bfgminer", "nbminer")
TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
PRUNE = {"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/mnt", "/media"}


# ---------------------------------------------------------------- resources
def metrics(cpu_interval: float = 0.5) -> dict:
    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    try:
        disk = psutil.disk_usage("/")
    except OSError:
        disk = None
    bat = None
    try:
        b = psutil.sensors_battery()
        if b is not None:
            bat = {"percent": round(b.percent, 1), "plugged": bool(b.power_plugged),
                   "minutes_left": None if b.secsleft in (psutil.POWER_TIME_UNLIMITED, psutil.POWER_TIME_UNKNOWN)
                   else round(b.secsleft / 60)}
    except Exception:
        pass
    temp = None
    try:
        t = psutil.sensors_temperatures()
        vals = [x.current for lst in t.values() for x in lst if x.current]
        temp = round(max(vals), 1) if vals else None
    except Exception:
        pass
    try:
        load = os.getloadavg()
    except OSError:
        load = (0, 0, 0)
    return {
        "cpu_percent": psutil.cpu_percent(interval=cpu_interval),
        "cpu_cores": psutil.cpu_count(logical=True),
        "load_avg": tuple(round(x, 2) for x in load),
        "ram_percent": vm.percent, "ram_used_gb": round(vm.used / 2**30, 2), "ram_total_gb": round(vm.total / 2**30, 2),
        "swap_percent": sw.percent,
        "disk_percent": disk.percent if disk else 0.0,
        "disk_used_gb": round(disk.used / 2**30, 1) if disk else 0, "disk_total_gb": round(disk.total / 2**30, 1) if disk else 0,
        "battery": bat, "temperature_c": temp,
        "uptime_h": round((time.time() - psutil.boot_time()) / 3600, 1),
    }


# ----------------------------------------------------------- critical folders
def dir_size(path: str, budget: float = 1.5) -> tuple[int, bool]:
    """Approximate recursive size (bytes). Returns (size, complete)."""
    end, total, stack = time.time() + budget, 0, [path]
    while stack:
        if time.time() > end:
            return total, False
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total, True


def human(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def critical_folders(sizes: bool = True) -> list[dict]:
    rows = []
    for path, max_mode, uid, desc in CRITICAL_PATHS:
        if not os.path.lexists(path):
            continue
        try:
            st = os.stat(path)
        except OSError:
            rows.append({"path": path, "desc": desc, "mode": "?", "owner": "?", "size": "?", "status": "OK",
                         "note": "not readable (run as root for a full audit)"})
            continue
        mode = stat.S_IMODE(st.st_mode)
        try:
            import pwd
            owner = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            owner = str(st.st_uid)
        status, notes = "OK", []
        extra = mode & ~max_mode & 0o7777
        if extra:
            status = "WARNING"
            notes.append(f"permissions {mode:04o} looser than expected {max_mode:04o}")
        if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
            status = "CRITICAL"
            notes.append("world-writable without sticky bit")
        if path == "/etc/shadow" and mode & 0o007:
            status = "CRITICAL"
            notes.append("password hashes readable by everyone")
        if uid is not None and st.st_uid != uid:
            status = "CRITICAL" if status == "CRITICAL" else "WARNING"
            notes.append(f"owned by {owner}, expected root")
        size = "-"
        if sizes and os.path.isdir(path) and path not in ("/", "/usr/bin", "/usr/sbin"):
            n, done = dir_size(path)
            size = ("" if done else "≥") + human(n)
        rows.append({"path": path, "desc": desc, "mode": f"{mode:04o}", "owner": owner,
                     "size": size, "status": status, "note": "; ".join(notes)})
    return rows


def check_ssh_config() -> list[str]:
    issues = []
    try:
        for line in open("/etc/ssh/sshd_config"):
            t = line.split("#")[0].split()
            if len(t) >= 2 and t[0].lower() == "permitrootlogin" and t[1].lower() == "yes":
                issues.append("sshd allows direct root login (PermitRootLogin yes)")
            if len(t) >= 2 and t[0].lower() == "permitemptypasswords" and t[1].lower() == "yes":
                issues.append("sshd allows empty passwords")
    except OSError:
        pass
    return issues


# ------------------------------------------------------------- filesystem scan
def filesystem_scan(root: str = "/", time_limit: float = 90.0, max_files: int = 600_000, progress=None) -> dict:
    """Walk the filesystem (no symlink following) looking for risky files."""
    t0 = time.time()
    res = {"world_writable": [], "suid_unusual": [], "tmp_executables": [], "files_checked": 0,
           "dirs_checked": 0, "truncated": False, "root": root, "seconds": 0.0}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath in PRUNE or any(dirpath.startswith(p + "/") for p in PRUNE):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in PRUNE]
        res["dirs_checked"] += 1
        in_tmp = dirpath.startswith(TEMP_DIRS)
        for name in filenames:
            p = os.path.join(dirpath, name)
            res["files_checked"] += 1
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            m = st.st_mode
            if m & (stat.S_ISUID | stat.S_ISGID):
                if name not in KNOWN_SUID or in_tmp or dirpath.startswith("/home"):
                    res["suid_unusual"].append(p)
            if m & stat.S_IWOTH and not in_tmp and not dirpath.startswith(("/proc", "/sys")):
                res["world_writable"].append(p)
            if in_tmp and m & 0o111:
                res["tmp_executables"].append(p)
            elif in_tmp:
                try:
                    with open(p, "rb") as f:
                        if f.read(4) == b"\x7fELF":
                            res["tmp_executables"].append(p)
                except OSError:
                    pass
        if progress and res["dirs_checked"] % 200 == 0:
            progress(res)
        if res["files_checked"] >= max_files or time.time() - t0 > time_limit:
            res["truncated"] = True
            break
    res["seconds"] = round(time.time() - t0, 1)
    return res


# -------------------------------------------------------------------- processes
def process_audit(top: int = 5) -> dict:
    procs, suspicious = [], []
    for p in psutil.process_iter(["pid", "name", "exe", "username", "cpu_percent", "memory_percent"]):
        try:
            i = p.info
            procs.append(i)
            exe = i.get("exe") or ""
            name = (i.get("name") or "").lower()
            if exe.startswith(TEMP_DIRS):
                suspicious.append((i, f"runs from {os.path.dirname(exe)}"))
            elif "(deleted)" in exe:
                suspicious.append((i, "executable deleted from disk"))
            elif any(m in name for m in MINER_NAMES):
                suspicious.append((i, "known crypto-miner name"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    top_cpu = sorted(procs, key=lambda x: x.get("cpu_percent") or 0, reverse=True)[:top]
    top_mem = sorted(procs, key=lambda x: x.get("memory_percent") or 0, reverse=True)[:top]
    return {"count": len(procs), "top_cpu": top_cpu, "top_mem": top_mem,
            "suspicious": [{"pid": i["pid"], "name": i["name"], "user": i.get("username"), "why": w} for i, w in suspicious]}


def listening_ports() -> list[dict]:
    out, seen = [], set()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return out
    for c in conns:
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        key = (c.laddr.port, c.laddr.ip)
        if key in seen:
            continue
        seen.add(key)
        exposed = c.laddr.ip in ("0.0.0.0", "::", "")
        name = "-"
        if c.pid:
            try:
                name = psutil.Process(c.pid).name()
            except Exception:
                pass
        out.append({"port": c.laddr.port, "addr": c.laddr.ip, "exposed": exposed, "proc": name,
                    "risky": c.laddr.port in RISKY_LISTEN and exposed, "service": RISKY_LISTEN.get(c.laddr.port, "")})
    return sorted(out, key=lambda x: x["port"])


# ---------------------------------------------------------------------- verdict
def build_features(m: dict, fs: dict, procs: dict, listeners: list, folders: list) -> dict:
    bat = m.get("battery")
    return {
        "cpu_percent": m["cpu_percent"], "ram_percent": m["ram_percent"],
        "disk_percent": m["disk_percent"], "swap_percent": m["swap_percent"],
        "world_writable": min(len(fs["world_writable"]), 30),
        "suid_unusual": min(len(fs["suid_unusual"]), 15),
        "risky_listeners": sum(1 for l in listeners if l["risky"]),
        "tmp_executables": min(len(fs["tmp_executables"]), 20),
        "suspicious_procs": len(procs["suspicious"]),
        "perm_issues": sum(1 for f in folders if f["status"] != "OK"),
        "battery_pct": bat["percent"] if bat else 100,
        "on_battery": int(bool(bat and not bat["plugged"])),
    }


def recommendations(m, fs, procs, listeners, folders, ssh) -> list[str]:
    r = []
    for f in folders:
        if f["status"] != "OK" and f["note"]:
            r.append(f"{f['path']}: {f['note']}")
    if fs["suid_unusual"]:
        r.append(f"Review {len(fs['suid_unusual'])} unexpected SUID/SGID file(s), e.g. {fs['suid_unusual'][0]}")
    if fs["world_writable"]:
        r.append(f"{len(fs['world_writable'])} world-writable file(s) outside temp dirs, e.g. {fs['world_writable'][0]}")
    if fs["tmp_executables"]:
        r.append(f"{len(fs['tmp_executables'])} executable(s) in temp directories, e.g. {fs['tmp_executables'][0]}")
    for s in procs["suspicious"]:
        r.append(f"Suspicious process {s['name']} (pid {s['pid']}): {s['why']}")
    for l in listeners:
        if l["risky"]:
            r.append(f"{l['service']} listening on all interfaces (port {l['port']}) — bind to localhost or firewall it")
    r += ssh
    if m["disk_percent"] >= 90:
        r.append(f"Disk is {m['disk_percent']}% full")
    if m["ram_percent"] >= 90:
        r.append(f"RAM usage is {m['ram_percent']}%")
    if m["cpu_percent"] >= 90:
        r.append(f"CPU usage is {m['cpu_percent']}%")
    b = m.get("battery")
    if b and b["percent"] <= 15 and not b["plugged"]:
        r.append(f"Battery low ({b['percent']}%) — plug in the charger")
    return r


def full_scan(root: str = "/", time_limit: float = 90.0, progress=None) -> dict:
    m = metrics()
    folders = critical_folders()
    fs = filesystem_scan(root, time_limit, progress=progress)
    procs = process_audit()
    listeners = listening_ports()
    ssh = check_ssh_config()
    feats = build_features(m, fs, procs, listeners, folders)
    v = ml.get("system").predict(feats)
    return {"metrics": m, "folders": folders, "filesystem": fs, "processes": procs,
            "listeners": listeners, "ssh_issues": ssh, "features": feats, "ml": v,
            "recommendations": recommendations(m, fs, procs, listeners, folders, ssh)}


def quick_status() -> dict:
    """Cheap resource-only reading for the live dashboard (no filesystem walk)."""
    m = metrics(cpu_interval=0.4)
    bat = m["battery"]
    feats = {"cpu_percent": m["cpu_percent"], "ram_percent": m["ram_percent"],
             "disk_percent": m["disk_percent"], "swap_percent": m["swap_percent"],
             "battery_pct": bat["percent"] if bat else 100, "on_battery": int(bool(bat and not bat["plugged"]))}
    return {"metrics": m, "ml": ml.get("system").predict(feats, explain=False)}
