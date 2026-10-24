"""Fan-out of live events to browser clients: packets are batched, alerts go out at once."""

import json
import queue
import threading
import time
from collections import deque
from typing import Any

from sentinel.contracts.models import (
    ArpEvent,
    DhcpEvent,
    Event,
    Flow,
    IncidentReport,
    MdnsEvent,
)
from sentinel.contracts.severity import severity_label
from sentinel.contracts.text import terminal_safe

MAX_PENDING = 5000  # events held between flushes; past this they are dropped and counted
MAX_BATCH = 150  # packets sent to the browser per flush; a heavier flush is sampled evenly
FLUSH_SECONDS = 0.1
STATUS_SECONDS = 1.0
_SUBSCRIBER_BACKLOG = 400
_RECENT_ALERTS = 25  # replayed to a client that connects (or reconnects) mid-session
_TEXT_LIMIT = 120


def _compact(event: Event) -> dict[str, Any]:
    """Short keys, hostile strings made inert. The browser renders them as text only."""
    if isinstance(event, Flow):
        return {
            "k": "f", "t": event.ts, "p": event.proto, "s": event.src_ip, "sp": event.src_port,
            "d": event.dst_ip, "dp": event.dst_port, "f": event.tcp_flags or "", "b": event.bytes,
            "m": event.src_mac,
            "q": terminal_safe(event.dns_query, _TEXT_LIMIT) if event.dns_query else "",
        }  # fmt: skip
    if isinstance(event, ArpEvent):
        return {
            "k": "arp",
            "t": event.ts,
            "s": event.sender_ip,
            "d": event.target_ip,
            "op": event.op,
        }
    if isinstance(event, DhcpEvent):
        return {"k": "dhcp", "t": event.ts, "s": event.src_ip, "m": event.msg_type}
    assert isinstance(event, MdnsEvent)  # noqa: S101 - Event is a closed union
    return {
        "k": "mdns",
        "t": event.ts,
        "s": event.src_ip,
        "n": terminal_safe(event.name, _TEXT_LIMIT),
    }


def _alert(report: IncidentReport) -> dict[str, Any]:
    inc, exp = report.incident, report.explanation
    return {
        "type": "alert", "t": inc.end_ts, "label": severity_label(inc.score).upper(),
        "score": round(inc.score, 2), "headline": terminal_safe(exp.headline, 200),
        "what": terminal_safe(exp.what_happened, 400), "chain": inc.chain, "incident": inc.id,
        "mac": inc.host_mac,
    }  # fmt: skip


class Hub:
    def __init__(self, capture: str, database: str) -> None:
        self._capture, self._database = capture, database
        self._lock = threading.Lock()
        self._subscribers: set[queue.Queue[str]] = set()
        self._pending: list[dict[str, Any]] = []
        self._recent: deque[dict[str, Any]] = deque(maxlen=_RECENT_ALERTS)
        self._counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self._events = 0
        self._dropped = 0
        self._since_status = 0
        self._last_status = time.monotonic()
        self._started = time.monotonic()
        self._state = "running"
        self._pps = 0.0
        self._last_event: float | None = None

    # ---- feeding (called from the capture thread) ---------------------------------------

    def add_event(self, event: Event) -> None:
        with self._lock:
            self._events += 1
            self._since_status += 1
            self._last_event = time.monotonic()
            if len(self._pending) >= MAX_PENDING:  # capture never blocks and memory stays bounded
                self._dropped += 1
                return
            self._pending.append(_compact(event))

    def add_report(self, report: IncidentReport) -> None:
        message = _alert(report)
        with self._lock:
            self._counts[message["label"]] += 1
            self._recent.append(message)
        self._publish("alert", message)

    def set_state(self, state: str) -> None:
        with self._lock:
            self._state = state

    # ---- clients --------------------------------------------------------------------------

    def subscribe(self) -> "queue.Queue[str]":
        client: queue.Queue[str] = queue.Queue(maxsize=_SUBSCRIBER_BACKLOG)
        with self._lock:
            self._subscribers.add(client)
        return client

    def unsubscribe(self, client: "queue.Queue[str]") -> None:
        with self._lock:
            self._subscribers.discard(client)

    def hello(self) -> dict[str, Any]:
        with self._lock:
            return {**self._status(), "recent": list(self._recent)}

    def health(self) -> dict[str, Any]:
        """What the Health tab shows about this run's capture."""
        with self._lock:
            quiet = None if self._last_event is None else round(time.monotonic() - self._last_event)
            return {**self._status(), "seconds_since_event": quiet}

    def _status(self) -> dict[str, Any]:
        return {
            "type": "status", "capture": self._capture, "state": self._state,
            "database": self._database, "events": self._events, "dropped": self._dropped,
            "pps": round(self._pps),
            "counts": dict(self._counts), "uptime": int(time.monotonic() - self._started),
        }  # fmt: skip

    def _publish(self, name: str, payload: dict[str, Any]) -> None:
        line = f"event: {name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"
        with self._lock:
            targets = list(self._subscribers)
        for client in targets:
            try:
                client.put_nowait(line)
            except queue.Full:  # a slow client loses its oldest message, never blocks capture
                try:
                    client.get_nowait()
                    client.put_nowait(line)
                except (queue.Empty, queue.Full):
                    pass

    # ---- periodic work --------------------------------------------------------------------

    def flush(self) -> None:
        with self._lock:
            batch, self._pending = self._pending, []
        if not batch:
            return
        total = len(batch)
        if total > MAX_BATCH:  # sample evenly so the animation still spans the whole interval
            step = total / MAX_BATCH
            batch = [batch[int(i * step)] for i in range(MAX_BATCH)]
        self._publish("batch", {"type": "batch", "n": total, "events": batch})

    def tick_status(self) -> None:
        now = time.monotonic()
        with self._lock:
            elapsed = max(now - self._last_status, 1e-6)
            self._pps = self._since_status / elapsed
            self._since_status, self._last_status = 0, now
            payload = self._status()
        self._publish("status", payload)

    def run(self, stop: threading.Event) -> None:
        last_status = time.monotonic()
        while not stop.wait(FLUSH_SECONDS):
            self.flush()
            if time.monotonic() - last_status >= STATUS_SECONDS:
                self.tick_status()
                last_status = time.monotonic()
