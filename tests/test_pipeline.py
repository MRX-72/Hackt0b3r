import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinel.api.service import SentinelService
from sentinel.config.secrets import Secrets
from sentinel.config.settings import Settings
from sentinel.contracts.models import Event, Flow, IncidentReport
from sentinel.net.http import Request, Response
from tests import scenarios as sc

SECRETS = Secrets.model_validate({"slack_webhook_url": "https://hooks.slack.test/services/SECRET"})
LLM_JSON = {
    "headline": "Device shows suspicious activity",
    "what_happened": "The device behaved in an unusual way on the network.",
    "likely_cause": "This may be unwanted software or a misconfigured tool.",
    "action_id": "investigate_device",
    "confidence_note": "This is an automatic estimate; please verify.",
}


class FakeWorld:
    """Fake Slack + Ollama; records every request body so tests can look for leaks."""

    def __init__(self, llm_reply: dict[str, str] | str | None = None) -> None:
        self.llm_reply = llm_reply
        self.slack: list[Request] = []
        self.llm: list[Request] = []

    def __call__(self, request: Request) -> Response:
        if "slack" in request.url:
            self.slack.append(request)
            return Response(200, b"ok")
        self.llm.append(request)
        reply = LLM_JSON if self.llm_reply is None else self.llm_reply
        content = reply if isinstance(reply, str) else json.dumps(reply)
        return Response(200, json.dumps({"message": {"content": content}}).encode())


def attack_pcap(tmp_path: Path) -> Path:
    packets = (
        sc.normal_browsing(0, 900, sc.USER)
        + sc.port_scan(100.0, range(1, 201))
        + sc.brute_force(300.0, 40)
        + sc.beacon(0, 20, 30.0, jitter=0.05)
        + sc.dns_tunnel(700.0, 60)
    )
    path = tmp_path / "attack.pcap"
    sc.write_pcap(path, packets)
    return path


_OPEN: list[SentinelService] = []


@pytest.fixture(autouse=True)
def _close_services() -> Iterator[None]:
    yield
    while _OPEN:
        _OPEN.pop().close()


def service(tmp_path: Path, world: FakeWorld, *, llm: bool = False) -> SentinelService:
    settings = Settings.model_validate(
        {
            "notify": {"enabled": True, "channels": ["slack"]},
            "storage": {"store_flows": True},
            "llm": {"enabled": llm, "model": "test-model"},
        }
    )
    svc = SentinelService(settings, SECRETS, world, database=tmp_path / "s.db")
    _OPEN.append(svc)
    return svc


def run(
    tmp_path: Path, world: FakeWorld, *, llm: bool = False, notify: bool = True
) -> tuple[SentinelService, list[IncidentReport], list[Event]]:
    svc = service(tmp_path, world, llm=llm)
    reports: list[IncidentReport] = []
    events: list[Event] = []
    svc.replay(
        attack_pcap(tmp_path), on_event=events.append, on_report=reports.append, notify=notify
    )
    return svc, reports, events


def test_end_to_end_replay_produces_correlated_incidents_and_stores_everything(
    tmp_path: Path,
) -> None:
    """Gate 1 shape: scan, brute force, beacon and DNS tunnel become two ATT&CK-tagged incidents."""
    svc, reports, events = run(tmp_path, FakeWorld())
    chains = {r.incident.host_mac: r.incident.chain for r in reports}
    assert chains[sc.MAC["attacker"]][:1] == ["T1046"]
    assert chains[sc.MAC["victim"]][:1] in (["T1071.001"], ["T1071.004"])
    stored = {i.host_mac: i for i in svc.incidents()}
    assert stored[sc.MAC["attacker"]].chain == ["T1046", "T1110"]
    assert set(stored[sc.MAC["victim"]].chain) == {"T1071.001", "T1071.004"}
    assert all(i.summary and i.status == "notified" for i in stored.values())
    # Every detector has real template text (none fell through to the generic default).
    assert not [r for r in reports if r.explanation.headline == "Unusual network activity"]
    assert svc.storage.conn.execute("SELECT COUNT(*) FROM alert").fetchone()[0] == 4
    assert svc.storage.conn.execute("SELECT COUNT(*) FROM flow").fetchone()[0] == sum(
        isinstance(e, Flow) for e in events
    )
    assert svc.storage.conn.execute("SELECT status FROM notification_delivery").fetchall()
    svc.close()


def test_normal_traffic_alone_produces_nothing(tmp_path: Path) -> None:
    path = tmp_path / "n.pcap"
    sc.write_pcap(path, sc.normal_browsing(0, 1800))
    svc = service(tmp_path, FakeWorld())
    reports: list[IncidentReport] = []
    summary = svc.replay(path, on_report=reports.append, notify=True)
    assert (summary.alerts, summary.incidents, reports) == (0, 0, [])
    assert summary.parse_errors == 0
    svc.close()


def test_notifications_are_off_in_replay_unless_requested(tmp_path: Path) -> None:
    world = FakeWorld()
    _, reports, _ = run(tmp_path, world, notify=False)
    assert reports and world.slack == [] and all(r.deliveries == [] for r in reports)


def test_slack_gets_one_message_per_new_chain_step_not_one_per_alert(tmp_path: Path) -> None:
    world = FakeWorld()
    run(tmp_path, world)
    assert 2 <= len(world.slack) <= 4  # 2 incidents, plus an update when a technique joins


def test_llm_text_is_used_when_faithful_and_hostile_data_never_reaches_it(tmp_path: Path) -> None:
    """R-SAF-004: tunnel labels from the pcap appear in no LLM prompt and no Slack payload."""
    world = FakeWorld()
    _, reports, _ = run(tmp_path, world, llm=True)
    assert world.llm and all(r.explanation.source == "llm" for r in reports)
    bodies = b" ".join((r.body or b"") for r in [*world.llm, *world.slack])
    assert b"example.com" not in bodies and b"badzone" not in bodies
    for req in world.llm:
        prompt = json.loads(req.body or b"")["messages"][1]["content"]
        assert set(json.loads(prompt)) == {
            "incident_id", "host_ip", "host_mac", "severity", "confidence", "score",
            "start_ts", "end_ts", "steps",
        }  # fmt: skip


@pytest.mark.parametrize(
    "reply", ["not json at all", {**LLM_JSON, "what_happened": "It sent 7777 probes."}]
)
def test_bad_llm_output_falls_back_to_templates_and_is_counted(
    tmp_path: Path, reply: dict[str, str] | str
) -> None:
    svc = service(tmp_path, FakeWorld(reply), llm=True)
    reports: list[IncidentReport] = []
    summary = svc.replay(attack_pcap(tmp_path), on_report=reports.append)
    assert reports and all(r.explanation.source == "template" for r in reports)
    assert summary.llm_used == 0 and summary.llm_rejected >= 1
    svc.close()


def test_flows_are_not_stored_by_default_and_retention_prunes_old_data(tmp_path: Path) -> None:
    svc = SentinelService(Settings(), SECRETS, FakeWorld(), database=tmp_path / "s.db")
    _OPEN.append(svc)
    pipeline = svc._pipeline(None, None, notify=False)
    for ts, frame in sc.port_scan(1000.0, range(1, 201)):
        pipeline.ingest(ts, frame)
    summary = pipeline.finish()
    assert (
        summary.flows > 0
        and svc.storage.conn.execute("SELECT COUNT(*) FROM flow").fetchone()[0] == 0
    )
    assert len(svc.storage.alerts_since(0)) == 1
    pruned = pipeline.prune(now=1000.0 + 31 * 86400)
    assert pruned["alerts"] == 1 and svc.storage.alerts_since(0) == []
