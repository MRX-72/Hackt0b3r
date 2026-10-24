"""Local web console: live packets, alerts and the permanent anomaly history.

An HTTP adapter over the service facade. It listens on 127.0.0.1 only, requires a per-run token
(set as a SameSite=Strict cookie), rejects foreign Host headers, serves vendored static files with
a strict Content-Security-Policy, and never builds HTML from network-derived strings (the page uses
textContent).
"""

import csv
import hmac
import io
import json
import queue
import re
import secrets
import threading
import time
import webbrowser
from collections.abc import Callable
from datetime import UTC, datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import ValidationError

from sentinel.api.hub import Hub
from sentinel.api.service import SentinelService, ServiceError
from sentinel.contracts.models import (
    MAC_PATTERN,
    AnomalyRecord,
    Channel,
    ChannelTest,
    Delivery,
    DeviceName,
    DoctorCheck,
    HistoryDelete,
    HistoryQuery,
)
from sentinel.storage.db import Storage

COOKIE = "sentinel"
MAC_RE = re.compile(MAC_PATTERN)
MAX_BODY = 16_384  # a delete request is at most 500 small integers
KEEPALIVE_SECONDS = 15.0
# A client that stalls mid-request is dropped, not given a thread forever.
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_STREAMS = 16  # live event streams at once; each holds a thread and a queue
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
STATIC_TYPES = {
    "app.js": "text/javascript",
    "tabs.js": "text/javascript",
    "app.css": "text/css",
    "index.html": "text/html",
}
CSV_COLUMNS = (
    "id", "time_utc", "source", "label", "detector", "technique", "host_ip", "target_ip",
    "score", "headline", "chain", "incident_id",
)  # fmt: skip
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def spreadsheet_safe(value: object) -> str:
    """Stop a cell being run as a formula when the CSV is opened in a spreadsheet."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def history_csv(rows: list[AnomalyRecord]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for r in rows:
        when = datetime.fromtimestamp(r.ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow(
            [spreadsheet_safe(v) for v in (
                r.id, when, r.source, r.label, r.detector, r.technique, r.host_ip, r.target_ip,
                f"{r.score:.2f}", r.headline, " > ".join(r.chain), r.incident_id,
            )]
        )  # fmt: skip
    return out.getvalue()


def parse_query(params: dict[str, list[str]]) -> HistoryQuery:
    """Build a validated HistoryQuery from a query string; raises ValueError for bad input."""
    raw: dict[str, Any] = {k: v[0] for k, v in params.items() if v and v[0] != ""}
    if "label" in raw:
        raw["label"] = raw["label"].upper()
    try:
        return HistoryQuery.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(str(exc.errors()[0]["loc"])) from exc


_DELIVERY_COLUMNS = {
    "channel": ("slack", "discord", "telegram"),
    "status": ("sent", "failed", "skipped"),
}
_DAY = 86400.0
_MAX_LIMIT = 500
_DOCTOR_CACHE_SECONDS = 10.0  # the checks touch the network and the LLM: not on every refresh


def parse_deliveries_query(params: dict[str, list[str]]) -> dict[str, Any]:
    """channel/status/limit/offset for the Notifications tab; raises ValueError on bad input."""
    out: dict[str, Any] = {"limit": 100, "offset": 0}
    for key, allowed in _DELIVERY_COLUMNS.items():
        if value := (params.get(key) or [""])[0]:
            if value not in allowed:
                raise ValueError(key)
            out[key] = value
    for key in ("limit", "offset"):
        if value := (params.get(key) or [""])[0]:
            if not value.isdigit() or not (key == "offset" or 1 <= int(value) <= _MAX_LIMIT):
                raise ValueError(key)
            out[key] = int(value)
    return out


class UiServer:
    def __init__(  # noqa: PLR0913 - the optional extras are what the console tabs need
        self, database: Path, hub: Hub, token: str, host: str, port: int, *,
        config_info: dict[str, Any] | None = None,
        doctor: Callable[[], list[DoctorCheck]] | None = None,
        notify_test: Callable[[Channel], Delivery] | None = None,
    ) -> None:  # fmt: skip
        self._database, self._hub, self._token = database, hub, token
        self._config_info, self._doctor, self._notify_test = config_info, doctor, notify_test
        self._doctor_cache: tuple[float, list[dict[str, Any]]] = (0.0, [])
        self._streams = 0
        self._streams_lock = threading.Lock()
        self._stop = threading.Event()
        allowed: set[str] = set()  # filled once the real port is known (port 0 = any free port)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "Sentinel"
            sys_version = ""
            timeout = REQUEST_TIMEOUT_SECONDS

            def log_message(self, *_: object) -> None:  # silence per-request logging
                pass

            # ---- plumbing ----
            def _headers(self, status: int, ctype: str, length: int | None = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                if length is not None:
                    self.send_header("Content-Length", str(length))
                self.send_header("Content-Security-Policy", CSP)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", "no-store")

            def _send(
                self, status: int, ctype: str, body: bytes, extra: dict[str, str] | None = None
            ) -> None:
                self._headers(status, ctype, len(body))
                for key, value in (extra or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def _json(self, payload: object, status: int = 200) -> None:
                self._send(status, "application/json", json.dumps(payload).encode())

            def _deny(self) -> None:
                self._send(HTTPStatus.FORBIDDEN, "text/plain; charset=utf-8", b"forbidden\n")

            def _origin_ok(self) -> bool:
                """A browser names the page that made a request; refuse any but this console.
                (Non-browser clients send no Origin header.)"""
                origin = self.headers.get("Origin")
                return origin is None or origin in {f"http://{h}" for h in allowed}

            def _cookie_ok(self) -> bool:
                jar: SimpleCookie = SimpleCookie(self.headers.get("Cookie", ""))
                morsel = jar.get(COOKIE)
                return morsel is not None and hmac.compare_digest(morsel.value, outer._token)

            # ---- routing ----
            def do_GET(self) -> None:  # noqa: PLR0911 - one early return per refusal or route
                if self.headers.get("Host", "") not in allowed or not self._origin_ok():
                    return self._deny()  # DNS-rebinding and cross-site guard
                url = urlsplit(self.path)
                params = parse_qs(url.query)
                if url.path == "/" and "t" in params:  # first visit: trade the token for a cookie
                    if not hmac.compare_digest(params["t"][0], outer._token):
                        return self._deny()
                    cookie = f"{COOKIE}={outer._token}; HttpOnly; SameSite=Strict; Path=/"
                    return self._send(HTTPStatus.FOUND, "text/plain; charset=utf-8", b"",
                                      {"Location": "/", "Set-Cookie": cookie})  # fmt: skip
                if not self._cookie_ok():
                    return self._deny()
                routes: dict[str, Callable[[], None]] = {
                    "/": lambda: self._static("index.html"),
                    "/static/app.js": lambda: self._static("app.js"),
                    "/static/tabs.js": lambda: self._static("tabs.js"),
                    "/static/app.css": lambda: self._static("app.css"),
                    "/api/stream": self._stream,
                    "/api/status": lambda: self._json(outer._hub.hello()),
                    "/api/history": lambda: self._history(params),
                    "/api/history.csv": lambda: self._history_csv(params),
                    "/api/notifications": lambda: self._notifications(params),
                    "/api/devices": self._devices,
                    "/api/health": self._health,
                }
                if url.path in routes:
                    return routes[url.path]()
                if url.path.startswith("/api/history/"):
                    return self._history_item(url.path.rsplit("/", 1)[1])
                if url.path.startswith("/api/devices/"):
                    return self._device(url.path.rsplit("/", 1)[1])
                self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"not found\n")

            def do_POST(self) -> None:
                if (
                    self.headers.get("Host", "") not in allowed
                    or not self._origin_ok()
                    or not self._cookie_ok()
                ):
                    return self._deny()
                # A custom header cannot be sent cross-site without a CORS preflight, which we
                # never answer: this plus the SameSite=Strict cookie stops other pages acting.
                actions: dict[str, Callable[[bytes], None]] = {
                    "/api/history/delete": self._post_history_delete,
                    "/api/devices/name": self._post_device_name,
                    "/api/notifications/test": self._post_notify_test,
                }
                if self.headers.get("X-Sentinel") != "1" or self.path not in actions:
                    return self._deny()
                try:
                    length = int(self.headers.get("Content-Length", ""))
                    if not 0 < length <= MAX_BODY:
                        raise ValueError("body size")
                    body = self.rfile.read(length)
                except ValueError:
                    return self._json({"error": "bad request"}, HTTPStatus.BAD_REQUEST)
                try:
                    actions[self.path](body)
                except ValidationError:
                    self._json({"error": "bad request"}, HTTPStatus.BAD_REQUEST)

            def _post_history_delete(self, body: bytes) -> None:
                request = HistoryDelete.model_validate_json(body)
                store = Storage(outer._database)
                try:
                    deleted = store.delete_anomalies(request.ids)
                finally:
                    store.close()
                self._json({"deleted": deleted})

            def _post_device_name(self, body: bytes) -> None:
                request = DeviceName.model_validate_json(body)
                store = Storage(outer._database)
                try:
                    found = store.set_device_name(request.mac, request.name)
                finally:
                    store.close()
                if not found:
                    return self._json({"error": "unknown device"}, HTTPStatus.NOT_FOUND)
                self._json({"ok": True})

            def _post_notify_test(self, body: bytes) -> None:
                request = ChannelTest.model_validate_json(body)
                info = outer._config_info or {}
                creds = info.get("notify", {}).get("credentials", {})
                if outer._notify_test is None or not creds.get(request.channel):
                    return self._json(
                        {"error": "channel has no credentials"}, HTTPStatus.BAD_REQUEST
                    )
                delivery = outer._notify_test(request.channel)
                store = Storage(outer._database)
                try:
                    store.audit("ui", "notify_test", request.channel, {"status": delivery.status})
                finally:
                    store.close()
                self._json({"status": delivery.status, "detail": delivery.detail})

            def _notifications(self, params: dict[str, list[str]]) -> None:
                try:
                    q = parse_deliveries_query(params)
                except ValueError as exc:
                    return self._json({"error": f"bad filter: {exc}"}, HTTPStatus.BAD_REQUEST)
                store = Storage(outer._database)
                try:
                    total, rows = store.deliveries(**q)
                    counts = store.delivery_counts(time.time() - _DAY)
                finally:
                    store.close()
                notify = (outer._config_info or {}).get("notify", {})
                self._json({"total": total, "counts": counts, "config": notify,
                            "rows": [r.model_dump(mode="json") for r in rows]})  # fmt: skip

            def _devices(self) -> None:
                store = Storage(outer._database)
                try:
                    devices = store.devices()
                finally:
                    store.close()
                self._json(
                    {"now": time.time(), "devices": [d.model_dump(mode="json") for d in devices]}
                )

            def _device(self, mac: str) -> None:
                store = Storage(outer._database)
                try:
                    mac = unquote(mac)
                    device = store.device(mac) if MAC_RE.match(mac) else None
                    recent = store.anomalies_of_device(mac) if device else []
                finally:
                    store.close()
                if device is None:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                self._json({"device": device.model_dump(mode="json"),
                            "alerts": [a.model_dump(mode="json") for a in recent]})  # fmt: skip

            def _health(self) -> None:
                store = Storage(outer._database)
                try:
                    database = {
                        "path": str(outer._database),
                        "bytes": outer._database.stat().st_size if outer._database.exists() else 0,
                        "alerts": store.count_rows("alert"),
                        "devices": store.count_rows("device"),
                        "history": sum(store.anomaly_label_counts().values()),
                        "deliveries": store.count_rows("notification_delivery"),
                        "incidents": store.incident_status_counts(),
                    }
                finally:
                    store.close()
                self._json({"runtime": outer._hub.health(), "config": outer._config_info,
                            "database": database, "checks": outer._checks()})  # fmt: skip

            def _static(self, name: str) -> None:
                body = (resources.files("sentinel.api") / "static" / name).read_bytes()
                self._send(HTTPStatus.OK, STATIC_TYPES[name] + "; charset=utf-8", body)

            def _query(self, params: dict[str, list[str]]) -> HistoryQuery | None:
                try:
                    return parse_query(params)
                except ValueError as exc:
                    self._json({"error": f"bad filter: {exc}"}, HTTPStatus.BAD_REQUEST)
                    return None

            def _history(self, params: dict[str, list[str]]) -> None:
                query = self._query(params)
                if query is None:
                    return
                store = Storage(outer._database)
                try:
                    total, rows = store.anomalies(query)
                    counts = store.anomaly_label_counts()
                finally:
                    store.close()
                self._json({"total": total, "counts": counts,
                            "rows": [r.model_dump(mode="json") for r in rows]})  # fmt: skip

            def _history_csv(self, params: dict[str, list[str]]) -> None:
                query = self._query(params)
                if query is None:
                    return
                store = Storage(outer._database)
                try:
                    _, rows = store.anomalies(query.model_copy(update={"limit": 500, "offset": 0}))
                finally:
                    store.close()
                disposition = 'attachment; filename="sentinel-history.csv"'
                self._send(
                    HTTPStatus.OK, "text/csv; charset=utf-8", history_csv(rows).encode(),
                    {"Content-Disposition": disposition},
                )  # fmt: skip

            def _history_item(self, raw_id: str) -> None:
                if not raw_id.isdigit():
                    return self._json({"error": "bad id"}, HTTPStatus.BAD_REQUEST)
                store = Storage(outer._database)
                try:
                    record = store.anomaly(int(raw_id))
                finally:
                    store.close()
                if record is None:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                self._json(record.model_dump(mode="json"))

            def _stream(self) -> None:
                with outer._streams_lock:
                    if outer._streams >= MAX_STREAMS:
                        busy = HTTPStatus.SERVICE_UNAVAILABLE
                        return self._send(busy, "text/plain; charset=utf-8", b"too many streams\n")
                    outer._streams += 1
                try:
                    self._serve_stream()
                finally:
                    with outer._streams_lock:
                        outer._streams -= 1

            def _serve_stream(self) -> None:
                client = outer._hub.subscribe()
                self._headers(HTTPStatus.OK, "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    hello = json.dumps(outer._hub.hello(), separators=(",", ":"))
                    self.wfile.write(f"event: hello\ndata: {hello}\n\n".encode())
                    self.wfile.flush()
                    while not outer._stop.is_set():
                        try:
                            message = client.get(timeout=KEEPALIVE_SECONDS)
                        except queue.Empty:
                            message = ": keepalive\n\n"
                        self.wfile.write(message.encode())
                        self.wfile.flush()
                except OSError:
                    pass  # the browser went away
                finally:
                    outer._hub.unsubscribe(client)

        self._server = ThreadingHTTPServer((host, port), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        allowed |= {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _checks(self) -> list[dict[str, Any]]:
        """`sentinel doctor` results, refreshed at most every few seconds."""
        if self._doctor is None:
            return []
        stamp, cached = self._doctor_cache
        if time.monotonic() - stamp > _DOCTOR_CACHE_SECONDS or not cached:
            try:
                cached = [c.model_dump() for c in self._doctor()]
            except Exception as exc:
                cached = [{"name": "checks", "ok": False, "detail": type(exc).__name__}]
            self._doctor_cache = (time.monotonic(), cached)
        return cached

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._server.shutdown()
        self._server.server_close()


def run_ui(  # noqa: PLR0913 - one keyword per command-line option
    service: SentinelService,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    iface: str | None = None,
    pcaps: list[Path] | None = None,
    speed: float = 20.0,
    notify: bool = False,
    open_browser: bool = True,
    say: Callable[[str], None] = lambda message: print(message, flush=True),
    stop: threading.Event | None = None,
) -> int:
    """Serve the console until Ctrl-C, capturing live or replaying files if asked."""
    pcaps = pcaps or []
    if iface and not pcaps:
        service.acquire_capture()  # fail now, not silently inside the capture thread
    capture = (
        f"replay {', '.join(p.name for p in pcaps)}"
        if pcaps
        else (f"live {iface}" if iface else "off")
    )
    hub = Hub(capture, str(service.database))
    token = secrets.token_urlsafe(24)
    try:
        server = UiServer(
            service.database,
            hub,
            token,
            host,
            port,
            config_info=service.console_info(notify_armed=notify),
            doctor=lambda: service.doctor(service.secrets_file),
            notify_test=service.notify_test,
        )
    except OSError as exc:
        raise ServiceError(f"cannot listen on {host}:{port}: {exc}") from exc
    stop = stop if stop is not None else threading.Event()

    def capture_loop() -> None:
        try:
            if pcaps:
                for pcap in pcaps:
                    service.replay(pcap, on_event=hub.add_event, on_report=hub.add_report,
                                   notify=notify, pace=speed, stop=stop)  # fmt: skip
                hub.set_state("replay finished")
            elif iface:
                service.watch(iface, on_event=hub.add_event, on_report=hub.add_report,
                              notify=notify, halt=stop)  # fmt: skip
                hub.set_state("capture ended")
        except ServiceError as exc:
            hub.set_state(f"error: {exc}")

    server.start()
    threads = [threading.Thread(target=hub.run, args=(stop,), daemon=True)]
    if pcaps or iface:
        threads.append(threading.Thread(target=capture_loop, daemon=True))
    for thread in threads:
        thread.start()
    url = f"http://127.0.0.1:{server.port}/?t={token}"
    say(f"Sentinel console: {url}")
    say(f"history database: {service.database.resolve()}   capture: {capture}   Ctrl-C to stop")
    if open_browser:
        webbrowser.open(url)
    try:
        while not stop.is_set():
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.stop()
        for thread in threads:
            thread.join(timeout=5)
    return 0
