import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinel.api.service import SentinelService
from sentinel.config.secrets import Secrets
from sentinel.config.settings import Settings
from sentinel.contracts.models import AnomalyRecord, HistoryQuery
from sentinel.storage.db import Storage
from tests import scenarios as sc
from tests.test_ui import record


def test_entries_cannot_be_edited_but_can_be_deleted_by_id_with_an_audit_trail(
    tmp_path: Path,
) -> None:
    store = Storage(tmp_path / "a.db")
    ids = [store.log_anomaly(record(ts=float(i), incident_id=f"inc-{i}")) for i in range(4)]
    assert ids == [1, 2, 3, 4] and store.anomaly(1) == record(
        ts=0.0, incident_id="inc-0"
    ).model_copy(update={"id": 1})
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("UPDATE anomaly_log SET headline = 'x'")
    assert store.delete_anomalies([2, 3, 99]) == 2  # 99 never existed
    assert [r.id for r in store.anomalies(HistoryQuery())[1]] == [4, 1]
    assert store.delete_anomalies([]) == 0
    entry = store.audit_entries()[-1]
    assert (entry.actor, entry.action, entry.target) == ("ui", "history_delete", "2 entries")
    assert entry.detail["ids"] == [2, 3, 99]
    store.close()


def test_retention_never_touches_the_permanent_history(tmp_path: Path) -> None:
    store = Storage(tmp_path / "a.db")
    store.log_anomaly(record(ts=1.0))
    store.prune(flows_before=10**9, alerts_before=10**9)
    assert store.anomaly_label_counts() == {"CRITICAL": 1}
    store.close()


def test_filters_combine_and_order_newest_first(tmp_path: Path) -> None:
    store = Storage(tmp_path / "a.db")
    for i, label in enumerate(["LOW", "HIGH", "CRITICAL", "CRITICAL"]):
        store.log_anomaly(record(label, float(i), headline=f"h{i}"))
    total, rows = store.anomalies(HistoryQuery(label="CRITICAL"))
    assert total == 2 and [r.headline for r in rows] == ["h3", "h2"]
    assert store.anomalies(HistoryQuery(since=1.0, until=3.0))[0] == 2
    assert store.anomalies(HistoryQuery(text="h1", label="HIGH"))[0] == 1
    assert store.anomalies(HistoryQuery(text="h1", label="LOW"))[0] == 0
    store.close()


@pytest.fixture
def service(tmp_path: Path) -> Iterator[SentinelService]:
    svc = SentinelService(Settings(), Secrets(), database=tmp_path / "s.db")
    yield svc
    svc.close()


def attack_pcap(tmp_path: Path) -> Path:
    path = tmp_path / "a.pcap"
    sc.write_pcap(path, sc.port_scan(100.0, range(1, 401)) + sc.brute_force(300.0, 40))
    return path


def test_every_report_is_logged_with_its_explanation_and_evidence(
    service: SentinelService, tmp_path: Path
) -> None:
    service.replay(attack_pcap(tmp_path))
    total, rows = service.history(HistoryQuery())
    assert total == 2
    newest, oldest = rows
    assert (oldest.detector, oldest.technique, oldest.label, oldest.source) == (
        "portscan", "T1046", "CRITICAL", "replay"
    )  # fmt: skip
    assert oldest.evidence["unique_dst_ports"] >= 400 and oldest.target_ip == sc.VICTIM[1]
    assert newest.chain == ["T1046", "T1110"] and newest.headline.startswith("Repeated login")
    assert "SSH" in newest.what_happened and newest.incident_id == oldest.incident_id


def test_live_runs_are_marked_live_and_survive_a_restart(
    service: SentinelService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frames = sorted(sc.port_scan(100.0, range(1, 401)), key=lambda p: p[0])

    def fake_capture(
        argv: list[str], duration: float | None = None, stop: threading.Event | None = None
    ) -> Iterator[tuple[float, bytes]]:
        return iter(frames)

    monkeypatch.setattr("sentinel.api.service.capture_live", fake_capture)
    service.watch("lo0")
    service.close()
    reopened = SentinelService(Settings(), Secrets(), database=tmp_path / "s.db")
    total, rows = reopened.history(HistoryQuery(source="live"))
    reopened.close()
    assert total == 1 and isinstance(rows[0], AnomalyRecord) and rows[0].label == "CRITICAL"
