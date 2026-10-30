"""Network scanner: IP geolocation risk rating + port scan + live connection monitor.

Risk rule (as specified for TriScan):
    local / private address   -> MEDIUM
    India                     -> SUSPICIOUS
    any other country         -> CRITICAL
A Random Forest then adds a threat score from behavioural features
(open/risky ports, hosting/proxy flag, reverse DNS, latency, connection count).
"""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

import requests

from core import ml

GEO_FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,query"
GEO_URL = "http://ip-api.com/json/{ip}"
GEO_BATCH = "http://ip-api.com/batch"

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS",
    445: "SMB", 1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}
SERVICE_NAMES = {22: "SSH", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
                 993: "IMAPS", 995: "POP3S", 5432: "PostgreSQL", 8080: "HTTP-alt", 8443: "HTTPS-alt",
                 **RISKY_PORTS}

LEVEL_RANK = {"MEDIUM": 1, "SUSPICIOUS": 2, "CRITICAL": 3}

_geo_cache: dict[str, dict | None] = {}


# ---------------------------------------------------------------- geolocation
def _clean(ip: str) -> str:
    return ip.strip().split("%")[0]


def geolocate(ip: str, timeout: float = 5.0) -> dict | None:
    ip = _clean(ip)
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        r = requests.get(GEO_URL.format(ip=ip), params={"fields": GEO_FIELDS}, timeout=timeout)
        data = r.json()
        geo = data if data.get("status") == "success" else None
    except Exception:
        geo = None
    _geo_cache[ip] = geo
    return geo


def geolocate_batch(ips, timeout: float = 8.0) -> None:
    """Fill the cache for many IPs with the free batch endpoint (100 per call)."""
    todo = [_clean(i) for i in ips if _clean(i) not in _geo_cache]
    for start in range(0, len(todo), 100):
        chunk = todo[start:start + 100]
        try:
            r = requests.post(GEO_BATCH, params={"fields": GEO_FIELDS},
                              json=[{"query": i} for i in chunk], timeout=timeout)
            for item in r.json():
                if item.get("status") == "success":
                    _geo_cache[item["query"]] = item
        except Exception:
            pass
        for i in chunk:
            _geo_cache.setdefault(i, None)


def classify(addr, geo: dict | None) -> tuple[str, str]:
    """Return (level, reason) using the TriScan geography rule."""
    if not addr.is_global:
        return "MEDIUM", "Local / private network address"
    if geo is None:
        return "SUSPICIOUS", "Public IP but location lookup failed (offline or rate-limited)"
    if geo.get("countryCode") == "IN":
        return "SUSPICIOUS", "Public IP located in India"
    return "CRITICAL", f"Public IP located outside India ({geo.get('country', '?')})"


def location_text(addr, geo: dict | None) -> str:
    if not addr.is_global:
        return "Local network (private address)"
    if not geo:
        return "Unknown"
    parts = [geo.get("city"), geo.get("regionName"), geo.get("country")]
    return ", ".join(p for p in parts if p)


# ------------------------------------------------------------------ port scan
def _probe(ip: str, port: int, timeout: float):
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, (time.perf_counter() - t0) * 1000
    except OSError:
        return port, None


def scan_ports(ip: str, ports=COMMON_PORTS, timeout: float = 0.8, workers: int = 64):
    """Plain TCP connect scan. Returns (open_ports, avg_latency_ms)."""
    open_ports, lat = [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for port, ms in ex.map(lambda p: _probe(ip, p, timeout), ports):
            if ms is not None:
                open_ports.append(port)
                lat.append(ms)
    return sorted(open_ports), (sum(lat) / len(lat) if lat else 0.0)


def reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(socket.gethostbyaddr, ip)
        try:
            return fut.result(timeout=timeout)[0]
        except (FutTimeout, OSError):
            return None


# ----------------------------------------------------------------- single IP
def scan_ip(ip: str, ports: bool = True) -> dict:
    ip = _clean(ip)
    addr = ipaddress.ip_address(ip)          # raises ValueError on bad input
    geo = geolocate(ip) if addr.is_global else None
    level, reason = classify(addr, geo)

    open_ports, latency = ([], 0.0)
    if ports:
        open_ports, latency = scan_ports(ip)
    rdns = reverse_dns(ip)
    risky = [p for p in open_ports if p in RISKY_PORTS]

    feats = {
        "is_private": int(not addr.is_global),
        "is_india": int(bool(geo and geo.get("countryCode") == "IN")),
        "open_ports": len(open_ports),
        "risky_ports": len(risky),
        "is_hosting_proxy": int(bool(geo and (geo.get("hosting") or geo.get("proxy")))),
        "no_reverse_dns": int(rdns is None),
        "latency_ms": round(latency, 1),
        "conn_count": 1,
    }
    verdict = ml.get("network").predict(feats)
    return {
        "ip": ip, "level": level, "reason": reason,
        "location": location_text(addr, geo), "geo": geo or {},
        "reverse_dns": rdns,
        "open_ports": [{"port": p, "service": SERVICE_NAMES.get(p, "?"), "risky": p in RISKY_PORTS}
                       for p in open_ports],
        "features": feats, "ml": verdict,
    }


# --------------------------------------------------------- live connections
def snapshot_connections() -> dict[str, dict]:
    """Group the machine's current remote connections by remote IP."""
    import psutil
    out: dict[str, dict] = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        conns = []
    for c in conns:
        if not c.raddr or c.status not in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT", "TIME_WAIT"):
            continue
        ip = _clean(c.raddr.ip)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_unspecified:
            continue
        d = out.setdefault(ip, {"ip": ip, "ports": set(), "count": 0, "procs": set()})
        d["ports"].add(c.raddr.port)
        d["count"] += 1
        if c.pid:
            try:
                d["procs"].add(psutil.Process(c.pid).name())
            except Exception:
                pass
    return out


def evaluate_connections(snapshot: dict[str, dict]) -> list[dict]:
    geolocate_batch([ip for ip in snapshot if ipaddress.ip_address(ip).is_global])
    detector = ml.get("network")
    rows = []
    for ip, d in snapshot.items():
        addr = ipaddress.ip_address(ip)
        geo = _geo_cache.get(ip) if addr.is_global else None
        level, reason = classify(addr, geo)
        risky = [p for p in d["ports"] if p in RISKY_PORTS]
        feats = {
            "is_private": int(not addr.is_global),
            "is_india": int(bool(geo and geo.get("countryCode") == "IN")),
            "open_ports": len(d["ports"]), "risky_ports": len(risky),
            "is_hosting_proxy": int(bool(geo and (geo.get("hosting") or geo.get("proxy")))),
            "no_reverse_dns": 0, "latency_ms": 60, "conn_count": d["count"],
        }
        v = detector.predict(feats, explain=False)
        rows.append({
            "ip": ip, "level": level, "location": location_text(addr, geo),
            "org": (geo or {}).get("isp", "") if geo else "",
            "ports": sorted(d["ports"]), "count": d["count"],
            "procs": sorted(d["procs"]), "ml": v,
        })
    rows.sort(key=lambda r: (-LEVEL_RANK[r["level"]], -r["ml"]["score"]))
    return rows


def monitor(interval: float = 4.0):
    """Generator: yields an evaluated snapshot of live connections every `interval` s."""
    while True:
        yield evaluate_connections(snapshot_connections())
        time.sleep(interval)
