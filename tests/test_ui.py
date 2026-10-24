import http.client
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from sentinel.api.hub import MAX_BATCH, Hub
from sentinel.api.service import SentinelService
from sentinel.api.ui import (
    COOKIE,
    CSP,
    UiServer,
    history_csv,
    parse_query,
    run_ui,
    spreadsheet_safe,
)
from sentinel.config.secrets import Secrets
from sentinel.config.settings import Settings
from sentinel.contracts.models import (
    AnomalyRecord,
    Explanation,
    Flow,
    HistoryQuery,
    Incident,
    IncidentReport,
)
from sentinel.storage.db import Storage
from tests import scenarios as sc

MAC = "aa:bb:cc:dd:ee:30"
STATIC = Path(__file__).resolve().parent.parent / "sentinel/api/static"


def record(label: str = "CRITICAL", ts: float = 1000.0, **over: object) -> AnomalyRecord:
    base: dict[str, object] = {
        "ts": ts, "logged_at": 2000.0, "source": "live", "detector": "portscan",
        "technique": "T1046", "severity": 0.9, "confidence": 0.9, "label": label, "score": 0.9,
        "host_mac": MAC, "host_ip": "192.168.2.30", "target_ip": "192.168.2.20",
        "headline": "Device is probing many network ports", "what_happened": "w",
        "likely_cause": "c", "action": "a", "chain": ["T1046"], "incident_id": "inc-1",
        "evidence": {"unique_dst_ports": 400.0},
    }  # fmt: skip
    return AnomalyRecord.model_validate(base | over)


def report(score: float = 0.95, headline: str = "Port scan") -> IncidentReport:
    return IncidentReport(
        incident=Incident(id="inc-1", host_mac=MAC, start_ts=1.0, end_ts=2.0, alerts=["a"],
                          chain=["T1046"], score=score),
        explanation=Explanation(headline=headline, what_happened="w", likely_cause="c",
                                action_id="monitor", suggested_action="s", confidence_note="n",
                                source="template"),
        deliveries=[],
    )  # fmt: skip


def flow(n: int, dns: str | None = None) -> Flow:
    return Flow(
        ts=1000.0 + n, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_mac=MAC, dst_mac=MAC,
        proto="tcp", src_port=40000, dst_port=22, bytes=60, packets=1, dns_query=dns,
    )  # fmt: skip


# ---------------------------------------------------------------------------- hub
def test_a_heavy_flush_is_sampled_but_reports_the_true_count() -> None:
    hub = Hub("live lo0", "hub-test.db")
    client = hub.subscribe()
    for i in range(1000):
        hub.add_event(flow(i))
    hub.flush()
    name, data = parse_sse(client.get_nowait())
    assert name == "batch" and data["n"] == 1000 and len(data["events"]) == MAX_BATCH
    stamps = [e["t"] for e in data["events"]]
    assert (
        stamps == sorted(stamps) and stamps[0] == 1000.0 and stamps[-1] > 1800
    )  # spans the interval


def test_alerts_are_pushed_immediately_counted_and_replayed_to_new_clients() -> None:
    hub = Hub("live lo0", "db")
    first = hub.subscribe()
    hub.add_report(report(0.95, "Port scan"))
    name, data = parse_sse(first.get_nowait())
    assert (name, data["label"], data["headline"]) == ("alert", "CRITICAL", "Port scan")
    hello = hub.hello()
    assert hello["counts"]["CRITICAL"] == 1 and hello["recent"][0]["headline"] == "Port scan"


def test_a_slow_client_loses_old_messages_and_never_blocks_capture() -> None:
    hub = Hub("live", "db")
    slow = hub.subscribe()
    started = time.monotonic()
    for i in range(2000):
        hub.add_report(report(0.5, f"alert {i}"))
    assert time.monotonic() - started < 3 and slow.qsize() <= 400


@pytest.mark.security
def test_network_strings_in_events_are_made_inert_before_they_leave_the_hub() -> None:
    hub = Hub("live", "db")
    client = hub.subscribe()
    hub.add_event(flow(1, dns="a\x1b[2J\x07.example.com"))
    hub.flush()
    _, data = parse_sse(client.get_nowait())
    assert "\x1b" not in data["events"][0]["q"] and "\\x1b" in data["events"][0]["q"]


def parse_sse(message: str) -> tuple[str, dict[str, Any]]:
    head, body = message.strip().split("\n", 1)
    return head.removeprefix("event: "), json.loads(body.removeprefix("data: "))


# ---------------------------------------------------------------------------- server
@pytest.fixture
def server(tmp_path: Path):  # type: ignore[no-untyped-def]
    db = tmp_path / "h.db"
    store = Storage(db)
    for i, (label, text) in enumerate(
        [("CRITICAL", "Port scan"), ("HIGH", "Beacon"), ("LOW", "50% done_x")]
    ):
        store.log_anomaly(record(label, 1000.0 + i, headline=text, incident_id=f"inc-{i}"))
    store.log_anomaly(
        record(
            "CRITICAL", 1010.0, headline="=HYPERLINK(evil)", source="replay", incident_id="inc-9"
        )
    )
    store.close()
    hub = Hub("off", str(db))
    ui = UiServer(db, hub, "tok", "127.0.0.1", 0)
    ui.start()
    yield ui, hub
    ui.stop()


def get(
    ui: UiServer, path: str, *, cookie: bool = True, host: str | None = None
) -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection("127.0.0.1", ui.port, timeout=5)
    headers = {"Host": host or f"127.0.0.1:{ui.port}"}
    if cookie:
        headers["Cookie"] = f"{COOKIE}=tok"
    conn.request("GET", path, headers=headers)
    return conn.getresponse()


@pytest.mark.security
def test_every_route_needs_the_token_cookie_and_a_local_host_header(
    server: tuple[UiServer, Hub],
) -> None:
    ui, _ = server
    for path in (
        "/",
        "/static/app.js",
        "/api/history",
        "/api/status",
        "/api/history.csv",
        "/api/history/1",
    ):
        assert get(ui, path, cookie=False).status == 403, path
    assert get(ui, "/api/history", host="evil.test").status == 403  # DNS-rebinding guard
    assert get(ui, "/?t=wrong", cookie=False).status == 403
    ok = get(ui, "/?t=tok", cookie=False)
    cookie = ok.getheader("Set-Cookie") or ""
    assert ok.status == 302 and "HttpOnly" in cookie and "SameSite=Strict" in cookie


@pytest.mark.security
def test_pages_carry_a_strict_content_security_policy(server: tuple[UiServer, Hub]) -> None:
    ui, _ = server
    for path in ("/", "/static/app.js", "/static/app.css", "/api/history"):
        res = get(ui, path)
        assert res.status == 200 and res.getheader("Content-Security-Policy") == CSP
        assert res.getheader("X-Content-Type-Options") == "nosniff"
    assert "script-src 'self'" in CSP and "unsafe" not in CSP and "default-src 'none'" in CSP


def test_history_filters_paging_and_counts(server: tuple[UiServer, Hub]) -> None:
    ui, _ = server
    data = json.loads(get(ui, "/api/history").read())
    assert data["total"] == 4 and data["counts"] == {"CRITICAL": 2, "HIGH": 1, "LOW": 1}
    assert data["rows"][0]["headline"] == "=HYPERLINK(evil)"  # newest first
    crit = json.loads(get(ui, "/api/history?label=critical&source=live").read())
    assert crit["total"] == 1 and crit["rows"][0]["headline"] == "Port scan"
    assert json.loads(get(ui, "/api/history?since=1001.5").read())["total"] == 2
    page = json.loads(get(ui, "/api/history?limit=1&offset=1").read())
    assert page["total"] == 4 and len(page["rows"]) == 1


def test_text_search_treats_percent_and_underscore_literally(server: tuple[UiServer, Hub]) -> None:
    ui, _ = server
    hit = json.loads(get(ui, "/api/history?text=50%25%20done_x").read())
    assert hit["total"] == 1
    assert json.loads(get(ui, "/api/history?text=%25").read())["total"] == 1  # only the literal '%'
    assert json.loads(get(ui, "/api/history?text=inc-1").read())["total"] == 1


@pytest.mark.security
@pytest.mark.parametrize(
    "query",
    ["label=SEVERE", "limit=0", "limit=5000", "offset=-1", "since=abc", "text=" + "x" * 101],
)
def test_bad_history_filters_are_rejected_not_executed(
    server: tuple[UiServer, Hub], query: str
) -> None:
    ui, _ = server
    res = get(ui, "/api/history?" + query)
    assert res.status == 400 and "bad filter" in json.loads(res.read())["error"]


@pytest.mark.security
def test_sql_text_in_filters_is_only_ever_data(server: tuple[UiServer, Hub]) -> None:
    ui, _ = server
    res = get(ui, "/api/history?text=%27%3B%20DROP%20TABLE%20anomaly_log%3B--")
    assert res.status == 200 and json.loads(res.read())["total"] == 0
    assert json.loads(get(ui, "/api/history").read())["total"] == 4


def test_one_entry_by_id_and_bad_ids(server: tuple[UiServer, Hub]) -> None:
    ui, _ = server
    item = json.loads(get(ui, "/api/history/1").read())
    assert item["id"] == 1 and item["evidence"] == {"unique_dst_ports": 400.0}
    assert get(ui, "/api/history/999").status == 404
    assert get(ui, "/api/history/1;drop").status == 400


@pytest.mark.security
def test_csv_export_neutralises_spreadsheet_formulas(server: tuple[UiServer, Hub]) -> None:
    ui, _ = server
    res = get(ui, "/api/history.csv")
    text = res.read().decode()
    assert res.status == 200 and res.getheader("Content-Type", "").startswith("text/csv")
    assert text.splitlines()[0].startswith("id,time_utc,source,label")
    assert "'=HYPERLINK(evil)" in text and ",=HYPERLINK" not in text
    assert [spreadsheet_safe(v) for v in ("=1", "+1", "-1", "@x", "ok", None)] == [
        "'=1",
        "'+1",
        "'-1",
        "'@x",
        "ok",
        "",
    ]
    assert history_csv([record(headline="@SUM(A1)")]).count("'@SUM") == 1


def test_unknown_paths_404_and_history_query_parser() -> None:
    assert parse_query({"label": ["high"], "limit": ["10"]}).label == "HIGH"
    with pytest.raises(ValueError):
        parse_query({"limit": ["9999"]})
    assert HistoryQuery().limit == 100


def read_until(sock: socket.socket, marker: bytes) -> bytes:
    seen = b""
    while marker not in seen:
        chunk = sock.recv(4096)
        assert chunk, f"connection closed before {marker!r}: {seen[:200]!r}"
        seen += chunk
    return seen


def test_the_live_stream_sends_hello_then_alerts(server: tuple[UiServer, Hub]) -> None:
    ui, hub = server
    sock = socket.create_connection(("127.0.0.1", ui.port), timeout=5)
    request = (
        f"GET /api/stream HTTP/1.1\r\nHost: 127.0.0.1:{ui.port}\r\nCookie: {COOKIE}=tok\r\n\r\n"
    )
    sock.sendall(request.encode())
    seen = read_until(sock, b"event: hello")
    assert b"text/event-stream" in seen
    hub.add_report(report(0.95, "Port scan"))
    seen += read_until(sock, b"event: alert")
    assert b"Port scan" in seen
    sock.close()


def post(
    ui: UiServer, body: bytes | str, *, cookie: bool = True, marker: bool = True,
    host: str | None = None, path: str = "/api/history/delete",
) -> http.client.HTTPResponse:  # fmt: skip
    conn = http.client.HTTPConnection("127.0.0.1", ui.port, timeout=5)
    headers = {"Host": host or f"127.0.0.1:{ui.port}", "Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = f"{COOKIE}=tok"
    if marker:
        headers["X-Sentinel"] = "1"
    conn.request("POST", path, body=body, headers=headers)
    return conn.getresponse()


def test_selected_entries_can_be_deleted_and_the_counts_follow(
    server: tuple[UiServer, Hub],
) -> None:
    ui, _ = server
    res = post(ui, json.dumps({"ids": [1, 4, 77]}))
    assert res.status == 200 and json.loads(res.read()) == {"deleted": 2}
    data = json.loads(get(ui, "/api/history").read())
    assert data["total"] == 2 and data["counts"] == {"HIGH": 1, "LOW": 1}
    assert get(ui, "/api/history/1").status == 404


@pytest.mark.security
def test_deleting_needs_the_cookie_a_local_host_and_the_same_origin_header(
    server: tuple[UiServer, Hub],
) -> None:
    ui, _ = server
    body = json.dumps({"ids": [1]})
    assert post(ui, body, cookie=False).status == 403
    assert post(ui, body, host="evil.test").status == 403
    assert post(ui, body, marker=False).status == 403  # a cross-site form cannot add this header
    assert post(ui, body, path="/api/history").status == 403
    assert json.loads(get(ui, "/api/history").read())["total"] == 4  # nothing was deleted


@pytest.mark.security
@pytest.mark.parametrize(
    "body",
    ["", "not json", "[]", '{"ids": []}', '{"ids": [0]}', '{"ids": [-1]}', '{"ids": ["1; DROP"]}',
     '{"ids": [1.5]}', '{"ids": [1], "extra": 1}', json.dumps({"ids": list(range(1, 502))}),
     " " * 20_000],
)  # fmt: skip
def test_malformed_delete_requests_are_rejected_without_deleting(
    server: tuple[UiServer, Hub], body: str
) -> None:
    ui, _ = server
    assert post(ui, body).status == 400
    assert json.loads(get(ui, "/api/history").read())["total"] == 4


# ---------------------------------------------------------------------------- static assets
@pytest.mark.security
def test_the_page_never_builds_html_from_strings() -> None:
    js = (STATIC / "app.js").read_text() + (STATIC / "tabs.js").read_text()
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        'setAttribute("style"',
    ):
        assert sink not in js, sink
    html = (STATIC / "index.html").read_text()
    assert (
        '<script src="/static/app.js">' in html
        and '<script src="/static/tabs.js">' in html
        and "onclick" not in html
        and "style=" not in html
    )
    assert (
        "http://" not in js + html + (STATIC / "app.css").read_text()
    )  # nothing fetched from elsewhere


# ---------------------------------------------------------------------------- end to end
def test_history_survives_restarts_and_the_runner_logs_what_it_sees(tmp_path: Path) -> None:
    pcap = tmp_path / "scan.pcap"
    sc.write_pcap(pcap, sc.port_scan(100.0, range(1, 401), per_second=400))
    db = tmp_path / "s.db"
    service = SentinelService(Settings(), Secrets(), database=db)
    said: list[str] = []
    stop = threading.Event()
    thread = threading.Thread(
        target=run_ui, args=(service,),
        kwargs={
            "port": 0, "pcaps": [pcap], "speed": 1000.0, "open_browser": False,
            "say": said.append, "stop": stop,
        },
    )  # fmt: skip
    thread.start()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not said:
        time.sleep(0.05)
    url = said[0].split(": ", 1)[1]
    port, token = int(url.split(":")[2].split("/")[0]), url.split("t=")[1]
    rows: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not rows:
        rows = json.loads(get_raw(port, "/api/history", token).read())["rows"]
        time.sleep(0.1)
    stop.set()
    thread.join(timeout=10)
    service.close()
    assert rows and rows[0]["detector"] == "portscan" and rows[0]["source"] == "replay"
    reopened = Storage(db)  # "after a reboot"
    total, found = reopened.anomalies(HistoryQuery())
    reopened.close()
    assert (
        total >= 1 and found[0].label == "CRITICAL" and found[0].evidence["unique_dst_ports"] >= 400
    )


def get_raw(port: int, path: str, token: str) -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Host": f"127.0.0.1:{port}", "Cookie": f"{COOKIE}={token}"})
    return conn.getresponse()


@pytest.mark.security
def test_a_client_that_stalls_mid_request_is_dropped(
    server: tuple[UiServer, Hub], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("sentinel.api.ui.REQUEST_TIMEOUT_SECONDS", 0.5)
    db = tmp_path / "t.db"
    Storage(db).close()
    ui = UiServer(db, Hub("off", str(db)), "tok", "127.0.0.1", 0)
    ui.start()
    try:
        sock = socket.create_connection(("127.0.0.1", ui.port), timeout=5)
        sock.sendall(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1")  # never finishes the request
        started = time.monotonic()
        assert sock.recv(100) == b""  # the server closed the connection
        assert time.monotonic() - started < 4
        sock.close()
    finally:
        ui.stop()
