"""Notifications, devices and health: storage, pipeline hooks and the console's JSON endpoints."""

import http.client
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from sentinel.api.hub import Hub
from sentinel.api.service import SentinelService
from sentinel.api.ui import COOKIE, UiServer, parse_deliveries_query
from sentinel.config.secrets import Secrets
from sentinel.config.settings import NotifySettings, Settings
from sentinel.contracts.models import Delivery, DoctorCheck, Incident
from sentinel.net.http import Request, Response
from sentinel.pipeline.run import _is_group
from sentinel.storage.db import DeviceSeen, Storage, load_migrations, migrate
from tests import scenarios as sc
from tests.test_ui import flow, record

MAC1, MAC2 = "aa:bb:cc:dd:ee:30", "aa:bb:cc:dd:ee:20"


def incident(inc_id: str = "inc-1", summary: str = "Port scan", score: float = 0.9) -> Incident:
    return Incident(id=inc_id, host_mac=MAC1, start_ts=1.0, end_ts=2.0, alerts=[], chain=["T1046"],
                    score=score, summary=summary)  # fmt: skip


# ----------------------------------------------------------------------------- storage
def test_deliveries_keep_what_was_said_and_filter(tmp_path: Path) -> None:
    store = Storage(tmp_path / "a.db")
    store.save_incident(incident(summary="the newest headline"))
    store.log_delivery(
        Delivery(channel="slack", status="sent", detail="ok"), "inc-1", "Port scan", "CRITICAL"
    )
    store.log_delivery(
        Delivery(channel="telegram", status="failed", detail="HTTP 500"), "inc-1", "Logins", "HIGH"
    )
    store.log_delivery(
        Delivery(channel="slack", status="skipped", detail="rate limit"), "inc-1"
    )  # old style
    total, rows = store.deliveries()
    assert total == 3
    assert [(r.channel, r.headline, r.label) for r in rows] == [
        ("slack", "the newest headline", "CRITICAL"),  # no stored text: falls back to the incident
        ("telegram", "Logins", "HIGH"),
        ("slack", "Port scan", "CRITICAL"),
    ]  # fmt: skip
    assert rows[1].error == "HTTP 500" and rows[2].error is None
    assert store.deliveries(channel="slack")[0] == 2 and store.deliveries(status="failed")[0] == 1
    assert store.deliveries(channel="slack", status="failed")[0] == 0
    assert len(store.deliveries(limit=1, offset=1)[1]) == 1
    assert store.delivery_counts(0.0) == {
        "slack": {"sent": 1, "skipped": 1},
        "telegram": {"failed": 1},
    }
    assert store.delivery_counts(10**12) == {}
    store.close()


def test_devices_accumulate_merge_ips_and_show_their_alerts(tmp_path: Path) -> None:
    store = Storage(tmp_path / "a.db")
    store.upsert_devices([DeviceSeen(MAC1, {"10.0.0.1"}, 10.0, 20.0, 5, 500, 50)])
    store.upsert_devices([DeviceSeen(MAC1, {"10.0.0.1", "10.0.0.9"}, 5.0, 30.0, 2, 200, 0),
                          DeviceSeen(MAC2, set(), 40.0, 41.0, 0, 0, 9)])  # fmt: skip
    store.log_anomaly(record("HIGH", 25.0, host_mac=MAC1, incident_id="i1"))
    store.log_anomaly(record("CRITICAL", 26.0, host_mac=MAC1, incident_id="i2"))
    one, two = store.devices()[1], store.devices()[0]
    assert two.mac == MAC2 and two.alerts == 0 and two.worst_label is None and two.ips == []
    assert (one.first_seen, one.last_seen, one.packets, one.bytes_out, one.bytes_in) == (
        5.0,
        30.0,
        7,
        700,
        50,
    )
    assert sorted(one.ips) == ["10.0.0.1", "10.0.0.9"]
    assert (one.alerts, one.worst_label, one.last_alert_ts) == (2, "CRITICAL", 26.0)
    assert store.device(MAC1) == one and store.device("aa:bb:cc:00:00:01") is None
    assert [a.incident_id for a in store.anomalies_of_device(MAC1)] == ["i2", "i1"]
    store.close()


def test_a_device_label_is_set_cleaned_cleared_and_audited(tmp_path: Path) -> None:
    store = Storage(tmp_path / "a.db")
    store.upsert_devices([DeviceSeen(MAC1, {"10.0.0.1"}, 1.0, 2.0)])
    assert store.set_device_name(MAC1, "  Lab laptop\x1b[2J  ") is True
    name = store.device(MAC1).name  # type: ignore[union-attr]
    assert (
        name == "Lab laptop\\x1b[2J" and "\x1b" not in name
    )  # shown as text, never a control code
    assert store.set_device_name(MAC1, "x" * 99) and len(store.device(MAC1).name or "") <= 40  # type: ignore[union-attr]
    assert store.set_device_name(MAC1, "   ") and store.device(MAC1).name is None  # type: ignore[union-attr]
    assert store.set_device_name(MAC2, "ghost") is False
    assert [e.action for e in store.audit_entries()] == ["device_label"] * 3
    store.close()


def test_upgrading_a_v5_database_keeps_old_deliveries_readable(tmp_path: Path) -> None:
    conn = sqlite3.connect(tmp_path / "old.db", isolation_level=None)
    conn.row_factory = sqlite3.Row
    migrate(conn, load_migrations()[:5])
    conn.close()
    store = Storage(tmp_path / "old.db")  # applies 006 and 007
    store.save_incident(incident())
    store.conn.execute("INSERT INTO notification_delivery (ts, channel, incident_id, status)"
                       " VALUES (1.0, 'slack', 'inc-1', 'sent')")  # fmt: skip
    assert store.deliveries()[1][0].headline == "Port scan"
    store.upsert_devices([DeviceSeen(MAC1, {"10.0.0.1"}, 1.0, 2.0, 1, 1, 1)])
    store.close()


# ----------------------------------------------------------------------------- pipeline
def test_group_addresses_are_recognised() -> None:
    for ip in ("224.0.0.251", "239.255.255.250", "ff02::fb", "255.255.255.255"):
        assert _is_group(ip), ip
    for ip in ("192.168.2.30", "10.0.0.1", "fe80::1", "223.1.1.1", "240.0.0.1", "127.0.0.1"):
        assert not _is_group(ip), ip


def replay_service(tmp_path: Path, sent: list[Request]) -> SentinelService:
    def transport(request: Request) -> Response:
        sent.append(request)
        return Response(200, b"ok")

    settings = Settings(notify=NotifySettings(enabled=True, channels=["slack"], retries=0))
    secrets = Secrets.model_validate({"slack_webhook_url": "https://hooks.slack.test/services/X"})
    return SentinelService(settings, secrets, transport, database=tmp_path / "s.db")


def test_a_replay_fills_the_inventory_and_the_notification_log(tmp_path: Path) -> None:
    pcap = tmp_path / "scan.pcap"
    sc.write_pcap(pcap, sc.port_scan(100.0, range(1, 401), per_second=400))
    sent: list[Request] = []
    service = replay_service(tmp_path, sent)
    service.replay(pcap, notify=True)
    devices = {d.mac: d for d in service.storage.devices()}
    attacker, victim = devices[MAC1], devices[MAC2]
    assert attacker.packets >= 400 and attacker.bytes_out > 0 and attacker.bytes_in > 0
    assert victim.bytes_in > 0 and attacker.ips == ["192.168.2.30"]
    assert (attacker.alerts, attacker.worst_label) == (1, "CRITICAL")
    _, rows = service.storage.deliveries()
    assert [(r.channel, r.status, r.label, r.headline) for r in rows] == [
        ("slack", "sent", "CRITICAL", "Device is probing many network ports")
    ]  # fmt: skip
    assert len(sent) == 1
    service.close()


# ----------------------------------------------------------------------------- endpoints
INFO: dict[str, Any] = {
    "version": "9.9", "python": "3.13",
    "capture": {"interface": "lo0", "snaplen": 384},
    "detectors": {"windows": [10], "cooldown_seconds": 15, "rules": ["portscan"], "ngram_dns": True,
                  "isolation_forest": True, "if_threshold": 0.6, "if_min_samples": 200},
    "notify": {"enabled": True, "armed": True, "channels": ["slack"], "min_severity": 0.6,
               "max_per_minute": 10,
               "credentials": {"slack": True, "discord": False, "telegram": False}},
    "llm": {"enabled": False, "runtime": "ollama", "model": ""},
}  # fmt: skip


class Console:
    def __init__(self, ui: UiServer, hub: Hub, doctor_calls: list[int], tests: list[str]) -> None:
        self.ui, self.hub, self.doctor_calls, self.tests = ui, hub, doctor_calls, tests

    def request(self, method: str, path: str, body: object = None, *, cookie: bool = True,
                marker: bool = True, origin: str | None = None) -> tuple[int, Any]:  # fmt: skip
        conn = http.client.HTTPConnection("127.0.0.1", self.ui.port, timeout=5)
        headers = {"Host": f"127.0.0.1:{self.ui.port}", "Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = f"{COOKIE}=tok"
        if marker and method == "POST":
            headers["X-Sentinel"] = "1"
        if origin is not None:
            headers["Origin"] = origin
        raw = body if isinstance(body, (str, bytes)) else json.dumps(body)
        conn.request(method, path, body=raw if method == "POST" else None, headers=headers)
        res = conn.getresponse()
        data = res.read()
        try:
            return res.status, json.loads(data)
        except ValueError:
            return res.status, data


@pytest.fixture
def console(tmp_path: Path):  # type: ignore[no-untyped-def]
    db = tmp_path / "c.db"
    store = Storage(db)
    store.save_incident(incident())
    store.log_delivery(
        Delivery(channel="slack", status="sent", detail="ok"), "inc-1", "Port scan", "CRITICAL"
    )
    store.log_delivery(
        Delivery(channel="telegram", status="failed", detail="HTTP 500"),
        "inc-1",
        "Port scan",
        "CRITICAL",
    )
    store.upsert_devices([DeviceSeen(MAC1, {"10.0.0.1"}, 1.0, 100.0, 3, 300, 30),
                          DeviceSeen(MAC2, {"10.0.0.2"}, 1.0, 50.0, 0, 0, 5)])  # fmt: skip
    store.log_anomaly(record("CRITICAL", 90.0, host_mac=MAC1, incident_id="inc-1"))
    store.close()
    hub = Hub("live lo0", str(db))
    doctor_calls: list[int] = []
    tests: list[str] = []

    def doctor() -> list[DoctorCheck]:
        doctor_calls.append(1)
        return [DoctorCheck(name="secrets file", ok=True, detail="fine"),
                DoctorCheck(name="llm server", ok=False, detail="not running")]  # fmt: skip

    def notify_test(channel: str) -> Delivery:
        tests.append(channel)
        return Delivery(channel="slack", status="sent", detail="ok")

    ui = UiServer(
        db, hub, "tok", "127.0.0.1", 0, config_info=INFO, doctor=doctor, notify_test=notify_test
    )
    ui.start()
    yield Console(ui, hub, doctor_calls, tests)
    ui.stop()


@pytest.mark.security
def test_the_new_endpoints_need_the_cookie_and_posts_need_the_marker(console: Console) -> None:
    for path in (
        "/api/notifications",
        "/api/devices",
        f"/api/devices/{MAC1}",
        "/api/health",
        "/static/tabs.js",
    ):
        assert console.request("GET", path, cookie=False)[0] == 403, path
    for path, body in (("/api/devices/name", {"mac": MAC1, "name": "x"}),
                       ("/api/notifications/test", {"channel": "slack"})):  # fmt: skip
        assert console.request("POST", path, body, cookie=False)[0] == 403
        assert console.request("POST", path, body, marker=False)[0] == 403
    assert console.tests == []
    assert all(d["name"] is None for d in console.request("GET", "/api/devices")[1]["devices"])


def test_notifications_endpoint_filters_counts_and_reports_the_run_setup(console: Console) -> None:
    status, data = console.request("GET", "/api/notifications")
    assert status == 200 and data["total"] == 2
    assert data["counts"] == {"slack": {"sent": 1}, "telegram": {"failed": 1}}
    assert data["config"]["armed"] is True and data["config"]["credentials"]["slack"] is True
    assert {r["headline"] for r in data["rows"]} == {"Port scan"}
    assert console.request("GET", "/api/notifications?status=failed")[1]["total"] == 1
    assert console.request("GET", "/api/notifications?channel=slack&status=failed")[1]["total"] == 0
    assert len(console.request("GET", "/api/notifications?limit=1&offset=1")[1]["rows"]) == 1


@pytest.mark.security
@pytest.mark.parametrize(
    "query",
    [
        "channel=email",
        "status=maybe",
        "limit=0",
        "limit=501",
        "limit=x",
        "offset=-1",
        "channel=slack%27%3B--",
    ],
)
def test_bad_notification_filters_are_rejected(console: Console, query: str) -> None:
    status, data = console.request("GET", "/api/notifications?" + query)
    assert status == 400 and "bad filter" in data["error"]


def test_the_query_parser_defaults() -> None:
    assert parse_deliveries_query({}) == {"limit": 100, "offset": 0}
    assert parse_deliveries_query({"channel": ["slack"], "limit": ["5"]}) == {
        "limit": 5, "offset": 0, "channel": "slack"}  # fmt: skip


def test_devices_list_and_detail_with_percent_encoded_macs(console: Console) -> None:
    status, data = console.request("GET", "/api/devices")
    assert status == 200 and [d["mac"] for d in data["devices"]] == [MAC1, MAC2]  # newest first
    assert data["devices"][0]["alerts"] == 1 and data["now"] > 0
    status, detail = console.request("GET", f"/api/devices/{MAC1.replace(':', '%3A')}")
    assert status == 200 and detail["device"]["ips"] == ["10.0.0.1"]
    assert [a["incident_id"] for a in detail["alerts"]] == ["inc-1"]
    for bad in ("nope", "aa:bb:cc:dd:ee:99", "..%2F..%2Fetc", "1;drop"):
        assert console.request("GET", "/api/devices/" + bad)[0] == 404, bad


def test_naming_a_device_through_the_console(console: Console) -> None:
    assert console.request("POST", "/api/devices/name", {"mac": MAC1, "name": "Lab laptop"}) == (
        200,
        {"ok": True},
    )
    assert console.request("GET", f"/api/devices/{MAC1}")[1]["device"]["name"] == "Lab laptop"
    assert (
        console.request("POST", "/api/devices/name", {"mac": "aa:bb:cc:dd:ee:99", "name": "x"})[0]
        == 404
    )
    for body in (
        "",
        "nope",
        {"mac": "bad", "name": "x"},
        {"mac": MAC1, "name": "x" * 41},
        {"mac": MAC1},
    ):
        assert console.request("POST", "/api/devices/name", body)[0] == 400, body
    assert console.request("GET", f"/api/devices/{MAC1}")[1]["device"]["name"] == "Lab laptop"


def test_a_test_notification_is_sent_only_for_channels_with_credentials(
    console: Console, tmp_path: Path
) -> None:
    status, data = console.request("POST", "/api/notifications/test", {"channel": "slack"})
    assert (status, data) == (200, {"status": "sent", "detail": "ok"}) and console.tests == [
        "slack"
    ]
    for channel in ("discord", "telegram"):  # configured nowhere
        assert console.request("POST", "/api/notifications/test", {"channel": channel})[0] == 400
    assert console.request("POST", "/api/notifications/test", {"channel": "email"})[0] == 400
    assert console.tests == ["slack"]
    store = Storage(Path(console.hub._database))
    assert [e.action for e in store.audit_entries()] == ["notify_test"]
    store.close()


def test_health_collects_runtime_config_database_and_checks(console: Console) -> None:
    status, data = console.request("GET", "/api/health")
    assert status == 200 and data["runtime"]["capture"] == "live lo0"
    assert data["runtime"]["seconds_since_event"] is None
    assert data["config"]["version"] == "9.9" and data["database"]["devices"] == 2
    assert data["database"]["history"] == 1 and data["database"]["deliveries"] == 2
    assert [(c["name"], c["ok"]) for c in data["checks"]] == [
        ("secrets file", True),
        ("llm server", False),
    ]
    console.request("GET", "/api/health")
    assert len(console.doctor_calls) == 1  # cached between refreshes


def test_a_crashing_check_cannot_break_the_health_page(tmp_path: Path) -> None:
    def boom() -> list[DoctorCheck]:
        raise RuntimeError("secret path /Users/x")

    db = tmp_path / "h.db"
    Storage(db).close()
    ui = UiServer(db, Hub("off", str(db)), "tok", "127.0.0.1", 0, config_info=INFO, doctor=boom)
    ui.start()
    try:
        status, data = Console(ui, Hub("x", "y"), [], []).request("GET", "/api/health")
    finally:
        ui.stop()
    assert status == 200 and data["checks"] == [
        {"name": "checks", "ok": False, "detail": "RuntimeError"}
    ]


def test_without_extras_the_endpoints_still_answer(tmp_path: Path) -> None:
    db = tmp_path / "n.db"
    Storage(db).close()
    ui = UiServer(db, Hub("off", str(db)), "tok", "127.0.0.1", 0)
    ui.start()
    try:
        c = Console(ui, Hub("x", "y"), [], [])
        assert c.request("GET", "/api/health")[1]["checks"] == []
        assert c.request("GET", "/api/notifications")[1]["config"] == {}
        assert c.request("POST", "/api/notifications/test", {"channel": "slack"})[0] == 400
    finally:
        ui.stop()


def test_the_hub_reports_how_long_the_capture_has_been_quiet() -> None:
    hub = Hub("live lo0", "db")
    assert hub.health()["seconds_since_event"] is None
    hub.add_event(flow(1))
    assert hub.health()["seconds_since_event"] == 0


def test_console_info_has_no_secrets(tmp_path: Path) -> None:
    secrets = Secrets.model_validate(
        {"slack_webhook_url": "https://hooks.slack.test/services/TOPSECRET"}
    )
    service = SentinelService(Settings(), secrets, database=tmp_path / "s.db")
    info = service.console_info(notify_armed=False)
    assert info["notify"]["credentials"] == {"slack": True, "discord": False, "telegram": False}
    assert "TOPSECRET" not in json.dumps(info) and info["notify"]["armed"] is False
    assert info["detectors"]["isolation_forest"] is True and info["version"]
    service.close()


@pytest.mark.security
def test_requests_from_other_web_pages_are_refused_even_with_every_credential(
    console: Console,
) -> None:
    port = console.ui.port
    ours = [f"http://127.0.0.1:{port}", f"http://localhost:{port}"]
    assert console.request("GET", "/api/devices", origin="https://evil.example")[0] == 403
    assert console.request("GET", "/api/devices", origin="null")[0] == 403
    assert console.request("GET", "/api/devices", origin=f"http://127.0.0.1:{port + 1}")[0] == 403
    body = {"mac": MAC1, "name": "pwned"}
    assert (
        console.request("POST", "/api/devices/name", body, origin="https://evil.example")[0] == 403
    )
    assert console.request("GET", f"/api/devices/{MAC1}")[1]["device"]["name"] is None
    for origin in (*ours, None):  # the console itself, and non-browser clients with no Origin
        assert console.request("GET", "/api/devices", origin=origin)[0] == 200
    assert console.request("POST", "/api/devices/name", body, origin=ours[0])[0] == 200
