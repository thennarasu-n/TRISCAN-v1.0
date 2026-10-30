"""Website scanner: crawls a whole site (same host) with *passive* checks only.

What it looks for
  * TLS problems, missing security headers, insecure cookies, mixed content
  * login forms over HTTP, forms posting to other domains, no-CSRF-token forms
  * malware indicators: hidden iframes, obfuscated JavaScript, crypto-miner
    signatures, scripts from suspicious hosts, executable downloads, meta redirects
  * bugs: 5xx errors, broken internal links, stack traces / SQL errors leaked to
    visitors, directory listings, version disclosure
  * common exposed files (.git/HEAD, .env, backups, phpinfo)  -- single GET each
It never sends attack payloads. Only scan sites you own or are authorised to test.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import random
import re
import socket
import ssl
import string
from collections import Counter
from urllib.parse import urljoin, urldefrag, urlparse

import requests
from bs4 import BeautifulSoup

from core import ml

UA = "TriScan/1.0 (+defensive security scanner)"
MAX_BYTES = 2_000_000
SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".css", ".woff", ".woff2",
            ".ttf", ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")
EXEC_EXT = (".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar", ".ps1", ".vbs", ".dmg", ".pif")
SUSP_TLDS = (".zip", ".mov", ".xyz", ".top", ".tk", ".gq", ".ml", ".cf", ".ga", ".click",
             ".country", ".kim", ".work", ".loan", ".men", ".icu", ".monster")
MINER_SIGS = ("coinhive", "coin-hive", "cryptonight", "cryptoloot", "minero.cc", "webminer",
              "jsecoin", "authedmine", "deepminer", "coinimp", "monerominer", "crypto-loot")

SEC_HEADERS = [
    ("Content-Security-Policy", "medium", "Missing Content-Security-Policy (XSS / injection hardening)"),
    ("Strict-Transport-Security", "medium", "Missing HSTS header (HTTPS downgrade protection)"),
    ("X-Frame-Options", "low", "Missing X-Frame-Options (clickjacking protection)"),
    ("X-Content-Type-Options", "low", "Missing X-Content-Type-Options: nosniff"),
    ("Referrer-Policy", "low", "Missing Referrer-Policy"),
]

OBFUSCATION = [
    (re.compile(r"eval\s*\(\s*(function|atob|unescape|String\.fromCharCode)", re.I), "eval() of decoded/packed code"),
    (re.compile(r"document\.write\s*\(\s*unescape\s*\(", re.I), "document.write(unescape(...))"),
    (re.compile(r"(?:\\x[0-9a-f]{2}){12,}", re.I), "long \\x hex-escaped string"),
    (re.compile(r"fromCharCode\s*\((?:\s*\d+\s*,){10,}", re.I), "String.fromCharCode() chain"),
    (re.compile(r"\bunescape\s*\(\s*['\"](?:%[0-9a-f]{2}){20,}", re.I), "long %-encoded unescape() payload"),
]
LEAK_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace exposed"),
    (re.compile(r"(Fatal error|Warning|Notice):.{0,120}on line \d+", re.I), "PHP error message exposed"),
    (re.compile(r"SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|Microsoft OLE DB", re.I), "SQL error message exposed"),
    (re.compile(r"\bat [\w.$]+\([\w]+\.java:\d+\)"), "Java stack trace exposed"),
    (re.compile(r"<title>\s*Index of /", re.I), "Directory listing enabled"),
]
PROBES = [
    ("/.git/HEAD", "critical", "Exposed .git repository", lambda r: r.text.strip().startswith("ref:")),
    ("/.env", "critical", "Exposed .env file (secrets)",
     lambda r: bool(re.search(r"^[A-Z][A-Z0-9_]{2,}=", r.text, re.M)) and "<html" not in r.text[:300].lower()),
    ("/phpinfo.php", "high", "phpinfo() page exposed", lambda r: "PHP Version" in r.text or "phpinfo()" in r.text),
    ("/backup.sql", "high", "SQL backup exposed", lambda r: bool(re.search(r"CREATE TABLE|INSERT INTO", r.text[:5000]))),
    ("/backup.zip", "high", "Backup archive exposed", lambda r: r.content[:2] == b"PK"),
    ("/config.php.bak", "high", "Config backup exposed", lambda r: "<?php" in r.text),
    ("/.DS_Store", "low", ".DS_Store file exposed", lambda r: r.content[:8] == b"\x00\x00\x00\x01Bud1"),
    ("/server-status", "medium", "Apache server-status exposed", lambda r: "Apache Server Status" in r.text),
    ("/.svn/entries", "medium", "Exposed .svn metadata", lambda r: r.status_code == 200 and len(r.text) > 0 and "<html" not in r.text[:200].lower()),
]

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Please enter a valid http(s) URL or domain")
    return raw


class WebsiteScanner:
    def __init__(self, url: str, max_pages: int = 30, timeout: float = 8.0, on_event=None):
        self.start_url = normalize_url(url)
        p = urlparse(self.start_url)
        self.host = p.hostname.lower()
        self.scheme = p.scheme
        self.max_pages = max_pages
        self.timeout = timeout
        self.on_event = on_event or (lambda kind, data: None)
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.verify = True
        self.findings: list[dict] = []
        self._seen: set = set()
        self.c: Counter = Counter()
        self.pages: list[dict] = []
        self.statuses: dict[str, int] = {}
        self.cookie_flagged: set = set()
        self.external_hosts: set = set()

    # --------------------------------------------------------------- helpers
    def add(self, sev: str, cat: str, title: str, url: str, detail: str = "", feature: str | None = None, count: int = 1):
        key = (title, url, detail)
        if key in self._seen:
            return
        self._seen.add(key)
        if feature:
            self.c[feature] += count
        f = {"severity": sev, "category": cat, "title": title, "url": url, "detail": detail}
        self.findings.append(f)
        self.on_event("finding", f)

    def _same_site(self, host: str | None) -> bool:
        if not host:
            return False
        h = host.lower()
        return h == self.host or h == "www." + self.host or "www." + h == self.host

    def _fetch(self, url: str):
        r = self.s.get(url, timeout=self.timeout, allow_redirects=True, stream=True, verify=self.verify)
        body = b""
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) > MAX_BYTES:
                break
        r._content = body
        r._content_consumed = True
        return r

    # ------------------------------------------------------------------- TLS
    def check_tls(self):
        if self.scheme != "https":
            self.add("medium", "Transport", "Site served over plain HTTP (no encryption)", self.start_url, feature="no_https")
            return
        port = urlparse(self.start_url).port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    cert = tls.getpeercert()
                    exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days = (exp - dt.datetime.utcnow()).days
                    if days < 0:
                        self.add("high", "Transport", "TLS certificate expired", self.start_url, f"expired {-days} days ago", "tls_problem")
                    elif days < 14:
                        self.add("medium", "Transport", "TLS certificate expires soon", self.start_url, f"{days} days left", "tls_problem")
                    if tls.version() in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self.add("high", "Transport", f"Outdated protocol negotiated ({tls.version()})", self.start_url, feature="tls_problem")
        except ssl.SSLCertVerificationError as e:
            self.verify = False
            self.add("high", "Transport", "TLS certificate failed verification", self.start_url, str(e.verify_message), "tls_problem")
        except (ssl.SSLError, OSError) as e:
            self.verify = False
            self.add("medium", "Transport", "TLS handshake problem", self.start_url, str(e)[:120], "tls_problem")

    # --------------------------------------------------------------- headers
    def check_headers(self, resp, url):
        h = resp.headers
        https = urlparse(resp.url).scheme == "https"
        for name, sev, msg in SEC_HEADERS:
            if name == "Strict-Transport-Security" and not https:
                continue
            if name in ("X-Frame-Options",) and "frame-ancestors" in h.get("Content-Security-Policy", ""):
                continue
            if name not in h:
                self.add(sev, "Headers", msg, url, feature="missing_sec_headers")
        srv = h.get("Server", "")
        if re.search(r"\d+\.\d+", srv):
            self.add("low", "Info leak", f"Server version disclosed: {srv}", url, feature="info_leaks")
        if "X-Powered-By" in h:
            self.add("low", "Info leak", f"X-Powered-By discloses stack: {h['X-Powered-By']}", url, feature="info_leaks")
        for ck in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []:
            name = ck.split("=", 1)[0].strip()
            low = ck.lower()
            problems = []
            if https and "secure" not in low:
                problems.append("Secure")
            if "httponly" not in low:
                problems.append("HttpOnly")
            if "samesite" not in low:
                problems.append("SameSite")
            if problems and name not in self.cookie_flagged:
                self.cookie_flagged.add(name)
                self.add("medium" if "Secure" in problems or "HttpOnly" in problems else "low", "Cookies",
                         f"Cookie '{name}' missing {', '.join(problems)}", url, feature="insecure_cookies")

    # ------------------------------------------------------------------ HTML
    def analyse_html(self, soup: BeautifulSoup, html: str, url: str, final_url: str):
        page_https = urlparse(final_url).scheme == "https"

        # --- forms
        for form in soup.find_all("form"):
            action = urljoin(final_url, form.get("action") or "")
            ap = urlparse(action)
            has_pw = bool(form.find("input", {"type": "password"}))
            if has_pw and (ap.scheme == "http" or not page_https):
                self.add("critical", "Forms", "Password form submitted over HTTP", url, action, "password_over_http")
            if ap.hostname and not self._same_site(ap.hostname):
                self.add("high" if has_pw else "medium", "Forms", f"Form posts to another domain ({ap.hostname})", url, feature="external_forms")
            if (form.get("method", "get").lower() == "post"
                    and not form.find("input", {"name": re.compile(r"csrf|token|nonce|authenticity", re.I)})):
                self.add("low", "Forms", "POST form without an obvious CSRF token", url, action)

        # --- iframes
        for fr in soup.find_all("iframe"):
            style = (fr.get("style") or "").replace(" ", "").lower()
            tiny = (fr.get("width") in ("0", "1") or fr.get("height") in ("0", "1")
                    or "display:none" in style or "visibility:hidden" in style
                    or re.search(r"(width|height):[01]px", style))
            src = fr.get("src") or ""
            if tiny:
                self.add("high", "Malware indicator", "Hidden / zero-size iframe", url, src[:120], "hidden_iframes")

        # --- scripts
        for sc in soup.find_all("script"):
            src = sc.get("src")
            if src:
                full = urljoin(final_url, src)
                host = urlparse(full).hostname or ""
                if host and not self._same_site(host):
                    self.external_hosts.add(host)
                    bad = host.endswith(SUSP_TLDS) or _is_ip(host)
                    if any(m in full.lower() for m in MINER_SIGS):
                        self.add("critical", "Malware indicator", "Crypto-miner script loaded", url, full, "miner_signatures")
                    elif bad:
                        self.add("medium", "Malware indicator", f"Script from suspicious host ({host})", url, full, "suspicious_script_hosts")
                if page_https and full.startswith("http://"):
                    self.add("medium", "Mixed content", "Script loaded over HTTP on an HTTPS page", url, full, "mixed_content")
            code = sc.string or sc.get_text() or ""
            if not code.strip():
                continue
            low = code.lower()
            for m in MINER_SIGS:
                if m in low:
                    self.add("critical", "Malware indicator", f"Crypto-miner signature in inline script ({m})", url, feature="miner_signatures")
                    break
            for rx, label in OBFUSCATION:
                if rx.search(code):
                    self.add("high", "Malware indicator", f"Obfuscated JavaScript: {label}", url, feature="obfuscated_js")
                    break
            else:
                if re.search(r"[A-Za-z0-9+/=]{400,}", code) and ("atob(" in code or "eval(" in code):
                    self.add("high", "Malware indicator", "Large encoded blob decoded at runtime", url, feature="obfuscated_js")

        # --- mixed content (images / styles / media)
        if page_https:
            for tag, attr in (("img", "src"), ("link", "href"), ("audio", "src"), ("video", "src"), ("source", "src")):
                for el in soup.find_all(tag):
                    v = el.get(attr) or ""
                    if v.startswith("http://"):
                        self.add("low", "Mixed content", f"<{tag}> loaded over HTTP on HTTPS page", url, v[:120], "mixed_content")

        # --- meta refresh redirect off-site
        for m in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            mm = re.search(r"url=(.+)", m.get("content", ""), re.I)
            if mm:
                tgt = urlparse(urljoin(final_url, mm.group(1).strip(" '\"")))
                if tgt.hostname and not self._same_site(tgt.hostname):
                    self.add("medium", "Malware indicator", f"Meta-refresh redirect to {tgt.hostname}", url, feature="cross_domain_redirects")

        # --- executable downloads + generator disclosure
        for a in soup.find_all("a", href=True):
            path = urlparse(a["href"]).path.lower()
            if path.endswith(EXEC_EXT):
                self.add("medium", "Malware indicator", f"Executable download link ({path.rsplit('/', 1)[-1]})", url, a["href"][:120], "exec_downloads")
        gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if gen and re.search(r"\d+\.\d+", gen.get("content", "")):
            self.add("low", "Info leak", f"CMS version disclosed: {gen['content']}", url, feature="info_leaks")

        # --- leaked errors / directory listing
        for rx, label in LEAK_PATTERNS:
            if rx.search(html):
                self.add("high" if "listing" not in label else "medium", "Bug", label, url, feature="info_leaks")

    def _links(self, soup, final_url):
        out = []
        for a in soup.find_all("a", href=True):
            u = urldefrag(urljoin(final_url, a["href"]))[0]
            p = urlparse(u)
            if (p.scheme in ("http", "https") and self._same_site(p.hostname)
                    and not p.path.lower().endswith(SKIP_EXT + EXEC_EXT)):
                out.append(u)
        return out

    # ----------------------------------------------------------------- probes
    def probe_sensitive_files(self):
        base = f"{self.scheme}://{urlparse(self.start_url).netloc}"
        for path, sev, title, ok in PROBES:
            try:
                r = self.s.get(base + path, timeout=self.timeout, allow_redirects=False, verify=self.verify)
                if r.status_code == 200 and ok(r):
                    self.add(sev, "Exposure", title, base + path, feature="exposed_files")
            except requests.RequestException:
                continue

    # -------------------------------------------------------------------- run
    def _features(self) -> dict:
        u = urlparse(self.start_url)
        total = max(1, len(self.statuses))
        broken = sum(1 for s in self.statuses.values() if s >= 400)
        c = self.c
        return {
            "no_https": c["no_https"], "tls_problem": min(1, c["tls_problem"]),
            "missing_sec_headers": min(5, c["missing_sec_headers"]),
            "insecure_cookies": c["insecure_cookies"], "mixed_content": min(10, c["mixed_content"]),
            "password_over_http": min(1, c["password_over_http"]), "external_forms": min(1, c["external_forms"]),
            "hidden_iframes": c["hidden_iframes"], "obfuscated_js": c["obfuscated_js"],
            "miner_signatures": min(1, c["miner_signatures"]), "exec_downloads": c["exec_downloads"],
            "suspicious_script_hosts": c["suspicious_script_hosts"], "info_leaks": c["info_leaks"],
            "exposed_files": c["exposed_files"], "broken_link_ratio": round(broken / total, 3),
            "url_is_ip": int(_is_ip(self.host)), "url_length": len(self.start_url),
            "host_dots": self.host.count("."),
            "suspicious_tld": int(self.host.endswith(SUSP_TLDS)),
            "cross_domain_redirects": c["cross_domain_redirects"],
        }

    def run(self) -> dict:
        self.on_event("status", "Checking TLS / transport security")
        self.check_tls()

        queue, visited = [self.start_url], set()
        first = True
        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            self.on_event("status", f"Scanning {url}")
            try:
                r = self._fetch(url)
            except requests.exceptions.SSLError as e:
                self.verify = False
                self.add("high", "Transport", "TLS error while fetching", url, str(e)[:120], "tls_problem")
                try:
                    r = self._fetch(url)
                except requests.RequestException:
                    self.statuses[url] = 599
                    continue
            except requests.RequestException as e:
                self.statuses[url] = 599
                if first:
                    self.add("critical", "Reachability", "Site could not be reached", url, type(e).__name__)
                first = False
                continue

            self.statuses[url] = r.status_code
            final = r.url
            if len(r.history):
                hops = {urlparse(h.headers.get("Location", "")).hostname for h in r.history} | {urlparse(final).hostname}
                off = [h for h in hops if h and not self._same_site(h)]
                if off:
                    self.add("medium", "Redirect", f"Redirects off-site to {off[0]}", url, feature="cross_domain_redirects")
            if first:
                self.check_headers(r, url)
                first = False
            if r.status_code >= 500:
                self.add("high", "Bug", f"Server error {r.status_code}", url)
            elif r.status_code >= 400:
                self.add("low", "Bug", f"Broken link / error {r.status_code}", url)

            ctype = r.headers.get("Content-Type", "")
            if "html" in ctype.lower() and r.content:
                html = r.content.decode(r.encoding or "utf-8", errors="replace")
                soup = BeautifulSoup(html, "html.parser")
                self.analyse_html(soup, html, url, final)
                for link in self._links(soup, final):
                    if link not in visited and link not in queue:
                        queue.append(link)
            self.pages.append({"url": url, "status": r.status_code})

            feats = self._features()
            v = ml.get("website").predict(feats, explain=False)
            self.on_event("progress", {"pages": len(visited), "queued": len(queue),
                                       "findings": len(self.findings), "score": v["score"]})

        self.on_event("status", "Probing for exposed sensitive files")
        self.probe_sensitive_files()
        return self.report()

    def report(self) -> dict:
        feats = self._features()
        v = ml.get("website").predict(feats)
        sev = Counter(f["severity"] for f in self.findings)
        mal = [f for f in self.findings if f["category"] == "Malware indicator"]

        # Final verdict: ML opinion, raised by hard rule-based evidence.
        verdict = v["label"]
        if feats["miner_signatures"] or (feats["hidden_iframes"] and feats["obfuscated_js"]):
            verdict = "MALICIOUS"
        elif (sev["critical"] or sev["high"]) and verdict == "SAFE":
            verdict = "SUSPICIOUS"
        safe = verdict == "SAFE"
        return {
            "url": self.start_url, "verdict": verdict, "safe": safe,
            "pages_scanned": len(self.pages), "findings": sorted(self.findings, key=lambda f: -SEV_RANK[f["severity"]]),
            "severity_counts": dict(sev), "malware_indicators": len(mal),
            "external_hosts": sorted(self.external_hosts), "features": feats, "ml": v,
        }


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
