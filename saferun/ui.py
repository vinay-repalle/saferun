"""Terminal presentation only: colours, icons, a spinner and a progress bar. No logic that affects results lives here.

Everything is opt-in by terminal capability: colours need a TTY (or --color always) and respect NO_COLOR / FORCE_COLOR / TERM=dumb;
the spinner needs a TTY on the stream it writes to (stderr, so stdout and JSON stay clean); unicode icons fall back to ASCII on
non-UTF-8 terminals. When none of that applies the plain text output is byte-for-byte what it always was.
"""
from __future__ import annotations

import itertools
import os
import shutil
import sys
import threading
import time

RESET = "\033[0m"
CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36", "white": "97",
         "bg_green": "42", "bg_yellow": "43", "bg_red": "41", "bg_magenta": "45", "black": "30"}
ICONS_UNICODE = {"ok": "✓", "bad": "✗", "warn": "!", "skip": "–", "dot": "•", "arrow": "→", "bar_full": "█", "bar_empty": "░"}
ICONS_ASCII = {"ok": "+", "bad": "x", "warn": "!", "skip": "-", "dot": "*", "arrow": "->", "bar_full": "#", "bar_empty": "."}
SPIN_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPIN_ASCII = "|/-\\"
# verdict banner / severity tag styles
VERDICT_STYLE = {"PASS": ("black", "bold", "bg_green"), "WARNING": ("black", "bold", "bg_yellow"), "FAIL": ("white", "bold", "bg_red")}
SEVERITY_STYLE = {"critical": ("bold", "magenta"), "high": ("bold", "red"), "medium": ("yellow",), "unknown": ("yellow",), "low": ("cyan",), "info": ("dim",)}


BANNER = (
    r" ____         __      ____              ",
    r"/ ___|  __ _ / _| ___|  _ \ _   _ _ __  ",
    r"\___ \ / _` | |_ / _ \ |_) | | | | '_ \ ",
    r" ___) | (_| |  _|  __/  _ <| |_| | | | |",
    r"|____/ \__,_|_|  \___|_| \_\\__,_|_| |_|",
)
BANNER_TAGLINE = "Check AI-generated code before you run or trust it"


class Theme:
    def __init__(self, color: bool = False, unicode_ok: bool = True):
        self.on = color
        self.icons = ICONS_UNICODE if unicode_ok else ICONS_ASCII
        self.spin = SPIN_UNICODE if unicode_ok else SPIN_ASCII

    def paint(self, text: str, *styles: str) -> str:
        if not self.on or not styles:
            return text
        return "\033[" + ";".join(CODES[s] for s in styles) + "m" + text + RESET

    def icon(self, name: str, *styles: str) -> str:
        return self.paint(self.icons[name], *styles)


PLAIN = Theme(False, True)


def _truthy(value: str | None) -> bool:
    return bool(value) and value != "0"


def theme_for(stream, mode: str = "auto") -> Theme:
    """Colour policy: `never` -> off; `always` -> on; `auto` -> on only for a real terminal, unless NO_COLOR (any value) or TERM=dumb,
    and on when FORCE_COLOR is set."""
    enc = (getattr(stream, "encoding", "") or "").lower()
    uni = enc.startswith("utf") and not _truthy(os.environ.get("SAFERUN_ASCII"))
    if mode == "never":
        return Theme(False, uni)
    if mode == "always":
        return Theme(True, uni)
    if os.environ.get("NO_COLOR"):
        return Theme(False, uni)
    if _truthy(os.environ.get("FORCE_COLOR")):
        return Theme(True, uni)
    tty = bool(getattr(stream, "isatty", lambda: False)()) and os.environ.get("TERM", "") != "dumb"
    return Theme(tty, uni)


def is_tty(stream) -> bool:
    try:
        return bool(stream.isatty()) and os.environ.get("TERM", "") != "dumb"
    except (AttributeError, ValueError):
        return False


class Spinner:
    """`with Spinner(sys.stderr, "Scanning…"):` animates a line while the body runs. Does nothing unless the stream is a terminal.
    Hides the cursor while spinning and always restores it and clears the line, also on Ctrl-C or an exception."""

    def __init__(self, stream, message: str, theme: Theme | None = None, interval: float = 0.1):
        self.stream, self.message, self.theme, self.interval = stream, message, theme or PLAIN, interval
        self.enabled = is_tty(stream)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = 0.0

    def _run(self) -> None:
        for frame in itertools.cycle(self.theme.spin):
            if self._stop.is_set():
                return
            secs = int(time.monotonic() - self._t0)
            room = max(10, shutil.get_terminal_size((100, 24)).columns - 10)      # one physical line, or \r would leave debris
            msg = self.message if len(self.message) <= room else self.message[: room - 1] + "…"
            line = f"{self.theme.paint(frame, 'cyan', 'bold')} {msg} {self.theme.paint(f'{secs}s', 'dim')}"
            self.stream.write("\r\033[K" + line)
            self.stream.flush()
            self._stop.wait(self.interval)

    def __enter__(self):
        if self.enabled:
            self._t0 = time.monotonic()
            self.stream.write("\033[?25l")           # hide the cursor
            self.stream.flush()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> bool:
        if self.enabled:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=2)
            self.stream.write("\r\033[K\033[?25h")    # clear the line, show the cursor again
            self.stream.flush()
        return False


def bar(done: float, total: float | None, theme: Theme, width: int = 24) -> str:
    """`[██████░░░░░░] 50%` (or `[####......] 50%`); an unknown total shows only the amount done by the caller."""
    if not total or total <= 0:
        return ""
    frac = max(0.0, min(1.0, done / total))
    n = int(round(frac * width))
    body = theme.paint(theme.icons["bar_full"] * n, "cyan") + theme.paint(theme.icons["bar_empty"] * (width - n), "dim")
    return f"[{body}] {int(frac * 100):3d}%"
