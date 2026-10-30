"""Dependency-free command-line UI helpers (ANSI colours, tables, bars)."""
from __future__ import annotations

import getpass
import itertools
import os
import re
import shutil
import sys
import threading
import time

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

CODES = {
    "reset": "0", "bold": "1", "dim": "2",
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "white": "37",
    "bred": "91", "bgreen": "92", "byellow": "93", "bblue": "94",
    "bmagenta": "95", "bcyan": "96",
}

LEVEL_STYLE = {
    "CRITICAL": ("bold", "bred"), "MALICIOUS": ("bold", "bred"),
    "NOT SAFE": ("bold", "bred"), "HIGH": ("bred",),
    "SUSPICIOUS": ("bold", "byellow"), "WARNING": ("bold", "byellow"),
    "MEDIUM": ("byellow",), "LOW": ("bcyan",), "INFO": ("dim",),
    "SAFE": ("bold", "bgreen"), "HEALTHY": ("bold", "bgreen"),
    "BENIGN": ("bold", "bgreen"), "OK": ("bgreen",),
}

BANNER = r"""
 _____ ____  ___ ____   ____    _    _   _
|_   _|  _ \|_ _/ ___| / ___|  / \  | \ | |
  | | | |_) || |\___ \| |     / _ \ |  \| |
  | | |  _ < | | ___) | |___ / ___ \| |\  |
  |_| |_| \_\___|____/ \____/_/   \_\_| \_|
"""


def c(text, *styles) -> str:
    if not USE_COLOR or not styles:
        return str(text)
    codes = ";".join(CODES[s] for s in styles)
    return f"\x1b[{codes}m{text}\x1b[0m"


def vlen(s: str) -> int:
    return len(_ANSI.sub("", s))


def trunc(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 140))


def level(text: str) -> str:
    return c(f"[{text}]", *LEVEL_STYLE.get(text.upper(), ("white",)))


def clear():
    if sys.stdout.isatty():
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()


def banner(subtitle: str = "Network · Website · System security scanner"):
    print(c(BANNER, "bcyan", "bold"))
    print(c("  " + subtitle, "dim"))
    print(c("  " + "─" * (width() - 4), "dim"))


def title(text: str):
    print()
    print(c(f"━━ {text} ", "bold", "bcyan") + c("━" * max(2, width() - len(text) - 4), "dim"))


def info(msg):  print(c("[*] ", "bblue") + str(msg))
def ok(msg):    print(c("[+] ", "bgreen") + str(msg))
def warn(msg):  print(c("[!] ", "byellow") + str(msg))
def err(msg):   print(c("[x] ", "bred") + str(msg))


def kv(pairs, indent: int = 2):
    """Aligned key/value list."""
    pairs = [(k, v) for k, v in pairs]
    if not pairs:
        return
    w = max(len(k) for k, _ in pairs)
    for k, v in pairs:
        print(" " * indent + c(k.ljust(w), "dim") + "  " + str(v))


def table(headers, rows, indent: int = 0):
    """Print a boxed table. Cells may contain ANSI colours."""
    rows = [[str(x) for x in r] for r in rows]
    cols = len(headers)
    widths = [vlen(h) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], vlen(r[i]))
    pad = " " * indent

    def line(l, m, r):
        return pad + c(l + m.join("─" * (w + 2) for w in widths) + r, "dim")

    def row(cells, bold=False):
        out = []
        for i, cell in enumerate(cells):
            text = c(cell, "bold") if bold else cell
            out.append(" " + text + " " * (widths[i] - vlen(cell)) + " ")
        sep = c("│", "dim")
        return pad + sep + sep.join(out) + sep

    print(line("┌", "┬", "┐"))
    print(row(headers, bold=True))
    print(line("├", "┼", "┤"))
    for r in rows:
        print(row(r))
    print(line("└", "┴", "┘"))


def box(lines, heading: str | None = None, style: str = "bcyan"):
    lines = [str(x) for x in lines]
    inner = max([vlen(x) for x in lines] + [vlen(heading or "") + 4, 40])
    if heading:
        top = "┌─ " + heading + " " + "─" * (inner - vlen(heading) - 2) + "┐"
    else:
        top = "┌" + "─" * (inner + 2) + "┐"
    print(c(top, style))
    for x in lines:
        print(c("│", style) + " " + x + " " * (inner - vlen(x)) + " " + c("│", style))
    print(c("└" + "─" * (inner + 2) + "┘", style))


def bar(pct: float, w: int = 24, warn_at: float = 70, crit_at: float = 90, invert: bool = False) -> str:
    """Coloured usage bar. invert=True means LOW is bad (e.g. battery)."""
    pct = max(0.0, min(100.0, float(pct)))
    filled = int(round(w * pct / 100))
    if invert:
        style = "bred" if pct <= 100 - crit_at else "byellow" if pct <= 100 - warn_at else "bgreen"
    else:
        style = "bred" if pct >= crit_at else "byellow" if pct >= warn_at else "bgreen"
    return c("█" * filled, style) + c("░" * (w - filled), "dim") + f" {pct:5.1f}%"


def score_bar(score: float, w: int = 24) -> str:
    """Threat score 0-100 (not a percentage): green < 35 <= yellow < 65 <= red."""
    return bar(score, w, warn_at=35, crit_at=65).rsplit(" ", 1)[0] + f" {float(score):5.1f}/100"


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(c("  ➜ ", "bcyan") + prompt + suffix + ": ").strip()
    except EOFError:
        raise KeyboardInterrupt
    return val or (default or "")


def ask_secret(prompt: str) -> str:
    try:
        return getpass.getpass(c("  ➜ ", "bcyan") + prompt + ": ")
    except EOFError:
        raise KeyboardInterrupt


def confirm(prompt: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    val = ask(f"{prompt} ({d})").lower()
    return default if not val else val.startswith("y")


def pause():
    try:
        input(c("\n  Press Enter to continue…", "dim"))
    except EOFError:
        pass


def live(text: str):
    """Overwrite the current terminal line (progress output)."""
    if sys.stdout.isatty():
        sys.stdout.write("\r\x1b[2K" + text)
        sys.stdout.flush()


def live_done():
    if sys.stdout.isatty():
        sys.stdout.write("\r\x1b[2K")
        sys.stdout.flush()


class Spinner:
    """with Spinner("Working…") as sp:  sp.update("Still working…")"""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, text: str):
        self.text = text
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def update(self, text: str):
        self.text = text

    def _run(self):
        for f in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            if sys.stdout.isatty():
                sys.stdout.write(f"\r\x1b[2K{c(f, 'bcyan')} {trunc(self.text, width() - 4)}")
                sys.stdout.flush()
            time.sleep(0.08)

    def __enter__(self):
        if sys.stdout.isatty():
            self._t.start()
        else:
            print(f"… {self.text}")
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._t.is_alive():
            self._t.join()
        live_done()
        return False
