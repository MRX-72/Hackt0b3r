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
from urllib.parse import parse_qs, urlsplit

from pydantic import ValidationError

from sentinel.api.hub import Hub
from sentinel.api.service import SentinelService, ServiceError
from sentinel.contracts.models import AnomalyRecord, HistoryDelete, HistoryQuery
from sentinel.storage.db import Storage

COOKIE = "sentinel"
MAX_BODY = 16_384  # a delete request is at most 500 small integers
KEEPALIVE_SECONDS = 15.0
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
STATIC_TYPES = {"app.js": "text/javascript", "app.css": "text/css", "index.html": "text/html"}
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


class UiServer:
    def __init__(self, database: Path, hub: Hub, token: str, host: str, port: int) -> None:
        self._database, self._hub, self._token = database, hub, token
        self._stop = threading.Event()
        allowed: set[str] = set()  # filled once the real port is known (port 0 = any free port)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "Sentinel"
            sys_version = ""

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

            def _cookie_ok(self) -> bool:
                jar: SimpleCookie = SimpleCookie(self.headers.get("Cookie", ""))
                morsel = jar.get(COOKIE)
                return morsel is not None and hmac.compare_digest(morsel.value, outer._token)

            # ---- routing ----
            def do_GET(self) -> None:
                if self.headers.get("Host", "") not in allowed:  # DNS-rebinding guard
                    return self._deny()
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
                    "/static/app.css": lambda: self._static("app.css"),
                    "/api/stream": self._stream,
                    "/api/status": lambda: self._json(outer._hub.hello()),
                    "/api/history": lambda: self._history(params),
                    "/api/history.csv": lambda: self._history_csv(params),
                }
                if url.path in routes:
                    return routes[url.path]()
                if url.path.startswith("/api/history/"):
                    return self._history_item(url.path.rsplit("/", 1)[1])
                self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"not found\n")

            def do_POST(self) -> None:
                if self.headers.get("Host", "") not in allowed or not self._cookie_ok():
                    return self._deny()
                # A custom header cannot be sent cross-site without a CORS preflight, which we
                # never answer: this plus the SameSite=Strict cookie stops other pages deleting.
                if self.headers.get("X-Sentinel") != "1" or self.path != "/api/history/delete":
                    return self._deny()
                try:
                    length = int(self.headers.get("Content-Length", ""))
                    if not 0 < length <= MAX_BODY:
                        raise ValueError("body size")
                    request = HistoryDelete.model_validate_json(self.rfile.read(length))
                except (ValueError, ValidationError):
                    return self._json({"error": "bad request"}, HTTPStatus.BAD_REQUEST)
                store = Storage(outer._database)
                try:
                    deleted = store.delete_anomalies(request.ids)
                finally:
                    store.close()
                self._json({"deleted": deleted})

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
        server = UiServer(service.database, hub, token, host, port)
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
