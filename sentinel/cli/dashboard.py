"""Full-screen live view: a sliding window of recent traffic under pinned CRITICAL alerts.

Presentation only. The terminal's size is read on every redraw, so the layout always fills the
window: a header bar, the pinned alerts, then as much recent traffic as still fits.
"""

import contextlib
import os
import re
import select
import shutil
import signal
import sys
import termios
import threading
import time
import tty
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TextIO

from sentinel.cli.render import format_event, severity_label
from sentinel.contracts.models import Event, IncidentReport
from sentinel.contracts.text import terminal_safe

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
MIN_COLS, MIN_ROWS = 40, 8
_FRAME_SECONDS = 0.05  # a new alert is on screen within this long
_IDLE_REDRAW_SECONDS = 0.5  # also redraws on its own, so a resized window repaints
_BUFFER_LINES = 2000
_PINNED = "CRITICAL"
_BADGE = {"CRITICAL": "1;97;41", "HIGH": "1;97;41", "MEDIUM": "1;30;43", "LOW": "1;30;46"}
_TEXT = {"CRITICAL": "1;31", "HIGH": "1;31", "MEDIUM": "33", "LOW": "36"}
_ALT_SCREEN_ON, _ALT_SCREEN_OFF = "\x1b[?1049h\x1b[?25l", "\x1b[?25h\x1b[?1049l"


def visible_length(text: str) -> int:
    return len(ANSI.sub("", text))


def _terminal_size() -> tuple[int, int]:
    size = shutil.get_terminal_size((100, 30))
    return size.columns, size.lines


def _fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


@dataclass
class _Pin:
    incident_id: str
    label: str
    score: float
    headline: str
    chain: str
    clock: str
    seq: int


@dataclass
class _Line:
    text: str
    kind: str  # "traffic" or "alert"
    label: str = ""


@dataclass
class Dashboard:
    title: str
    color: bool = True
    show_traffic: bool = True
    out: TextIO = field(default_factory=lambda: sys.stdout)
    size: Callable[[], tuple[int, int]] = field(default_factory=lambda: _terminal_size)
    keys: bool = True

    def __post_init__(self) -> None:
        self._lock = threading.RLock()
        self._lines: deque[_Line] = deque(maxlen=_BUFFER_LINES)
        self._pins: dict[str, _Pin] = {}
        self._labels: dict[str, str] = {}
        self._events = 0
        self._seq = 0
        self._started = time.monotonic()
        self._dirty = True
        self._finished = False
        self._last_size: tuple[int, int] | None = None
        self._stop = threading.Event()
        self._quit = threading.Event()
        self._waiting = threading.Event()
        self._threads: list[threading.Thread] = []
        self._tty_state: list[object] | None = None
        self._old_sigint: Any = None

    # ---- feeding -------------------------------------------------------------------------

    def add_event(self, event: Event, *, show: bool = True) -> None:
        with self._lock:
            self._events += 1
            if show and self.show_traffic:
                self._lines.append(_Line(format_event(event), "traffic"))
            self._dirty = True

    def add_report(self, report: IncidentReport) -> None:
        """An alert: always listed in the stream; CRITICAL ones are pinned to the top."""
        inc, exp = report.incident, report.explanation
        label = severity_label(inc.score)
        headline = terminal_safe(exp.headline)
        with self._lock:
            self._labels[inc.id] = label
            chain = " > ".join(inc.chain)
            alert = f"ALERT [{label} {inc.score:.2f}] {headline} ({chain})"
            self._lines.append(_Line(alert, "alert", label))
            if label == _PINNED:
                self._seq += 1
                clock = time.strftime("%H:%M:%S", time.localtime(inc.end_ts))
                self._pins[inc.id] = _Pin(
                    inc.id, label, inc.score, headline, chain, clock, self._seq
                )
            self._dirty = True

    def clear_pins(self) -> None:
        with self._lock:
            self._pins.clear()
            self._dirty = True

    # ---- layout --------------------------------------------------------------------------

    def _style(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def frame(self) -> list[str]:
        """Exactly `rows` lines, none wider than `cols` once colour codes are ignored."""
        cols, rows = self.size()
        with self._lock:
            if rows < MIN_ROWS or cols < MIN_COLS:
                note = [f"terminal too small: need {MIN_COLS}x{MIN_ROWS}, have {cols}x{rows}"]
                return ([_fit(n, cols) for n in note] + [""] * rows)[:rows]
            body = self._header(cols) + self._pinned(cols, rows) + self._stream(cols, rows)
        return body[:rows]

    def _header(self, cols: int) -> list[str]:
        counts: dict[str, int] = {}
        for label in self._labels.values():
            counts[label] = counts.get(label, 0) + 1
        elapsed = int(time.monotonic() - self._started)
        state = "FINISHED  q to exit" if self._finished else "q quit  c clear pins"
        text = (
            f" SENTINEL | {self.title} | {elapsed // 60:02d}:{elapsed % 60:02d} | "
            f"events {self._events} | CRIT {counts.get('CRITICAL', 0)} "
            f"HIGH {counts.get('HIGH', 0)} MED {counts.get('MEDIUM', 0)} "
            f"LOW {counts.get('LOW', 0)} | {state}"
        )
        return [self._style(_fit(text, cols).ljust(cols), "7")]  # reverse video bar

    def _budget(self, rows: int) -> tuple[int, int]:
        """(pinned lines, traffic lines) for a window of `rows` lines."""
        free = rows - 3  # header + two section titles
        pinned = max(1, min(len(self._pins) or 1, free // 2))
        return pinned, free - pinned

    def _pinned(self, cols: int, rows: int) -> list[str]:
        slots, _ = self._budget(rows)
        pins = sorted(self._pins.values(), key=lambda p: p.seq, reverse=True)  # newest first
        title = f" PINNED: CRITICAL ALERTS ({len(pins)})  newest on top, kept until cleared"
        out = [self._style(_fit(title, cols), "1;31")]
        if not pins:
            return [*out, self._style(_fit("   none yet", cols), "2")]
        shown = pins if len(pins) <= slots else pins[: slots - 1]
        for pin in shown:
            badge = f" {pin.label} {pin.score:.2f} "
            rest = _fit(
                f" {pin.clock}  {pin.headline}  ({pin.chain})  {pin.incident_id}", cols - len(badge)
            )
            out.append(self._style(badge, _BADGE[pin.label]) + self._style(rest, _TEXT[pin.label]))
        if len(pins) > len(shown):
            more = f"   ... +{len(pins) - len(shown)} older critical alerts"
            out.append(self._style(_fit(more, cols), "1;31"))
        return out

    def _stream(self, cols: int, rows: int) -> list[str]:
        _, slots = self._budget(rows)
        shown = self._lines if self.show_traffic else [x for x in self._lines if x.kind == "alert"]
        tail = list(shown)[-slots:]
        title = (
            " RECENT TRAFFIC (sliding window)" if self.show_traffic else " ALERTS (traffic hidden)"
        )
        out = [self._style(_fit(title, cols), "1")]
        for line in tail:
            text = _fit(line.text, cols)
            out.append(
                self._style(text, _TEXT[line.label])
                if line.kind == "alert"
                else self._style(text, "2")
            )
        return out + [""] * (slots - len(tail))

    def pinned_summary(self) -> list[str]:
        """What to leave on the normal screen after the view closes."""
        with self._lock:
            pins = sorted(self._pins.values(), key=lambda p: p.seq, reverse=True)
        return [
            f"[{p.label} {p.score:.2f}] {p.clock}  {p.headline}  ({p.chain})  {p.incident_id}"
            for p in pins
        ]

    # ---- terminal ------------------------------------------------------------------------

    def _draw(self) -> None:
        with self._lock:
            size = self.size()
            lines = self.frame()
            clear = "\x1b[2J" if size != self._last_size else ""
            self._last_size, self._dirty = size, False
        body = "".join(f"\x1b[{i};1H{line}\x1b[K" for i, line in enumerate(lines, 1))
        self.out.write(clear + body)
        self.out.flush()

    def _render_loop(self) -> None:
        last = 0.0
        while not self._stop.wait(_FRAME_SECONDS):
            if self._dirty or time.monotonic() - last >= _IDLE_REDRAW_SECONDS:
                self._draw()
                last = time.monotonic()

    def _key_loop(self) -> None:
        while not self._stop.is_set():
            if select.select([sys.stdin], [], [], 0.1)[0]:
                key = sys.stdin.read(1).lower()
                if key == "c":
                    self.clear_pins()
                elif key == "q":
                    self._quit.set()
                    if not self._waiting.is_set():
                        os.kill(os.getpid(), signal.SIGINT)  # same as Ctrl-C: stop capturing

    def finish_and_wait(self) -> None:
        """Mark the run as over and keep the screen until the user presses q (or Ctrl-C)."""
        with self._lock:
            self._finished = True
            self._dirty = True
        self._waiting.set()
        if self.keys and sys.stdin.isatty() and not self._quit.is_set():
            with contextlib.suppress(KeyboardInterrupt):
                self._quit.wait()

    def _on_sigint(self, _signum: int, _frame: object) -> None:
        self._quit.set()  # the user asked to leave: do not wait for another key afterwards
        raise KeyboardInterrupt

    def __enter__(self) -> "Dashboard":
        with contextlib.suppress(ValueError):  # only the main thread may install handlers
            self._old_sigint = signal.signal(signal.SIGINT, self._on_sigint)
        self.out.write(_ALT_SCREEN_ON)
        if self.keys and sys.stdin.isatty():
            self._tty_state = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
            self._threads.append(threading.Thread(target=self._key_loop, daemon=True))
        self._threads.append(threading.Thread(target=self._render_loop, daemon=True))
        for thread in self._threads:
            thread.start()
        self._draw()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=1)
        if self._old_sigint is not None:
            signal.signal(signal.SIGINT, self._old_sigint)
        self._draw()
        if self._tty_state is not None:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._tty_state)  # type: ignore[arg-type]
        self.out.write(_ALT_SCREEN_OFF)
        self.out.flush()
