import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinel.contracts.models import Alert, Flow, Incident
from sentinel.storage.db import FLOWS_FOR_HOST_SQL, Storage, StorageError, load_migrations, migrate

A = "aa:bb:cc:dd:ee:01"
B = "aa:bb:cc:dd:ee:02"


def flow(ts: float, src: str = A, dst: str = B, **over: object) -> Flow:
    base: dict[str, object] = {
        "ts": ts, "src_ip": "192.168.2.3", "dst_ip": "192.168.2.2", "src_mac": src,
        "dst_mac": dst, "proto": "tcp", "src_port": 51234, "dst_port": 22, "bytes": 60,
        "packets": 1, "tcp_flags": "S",
    }  # fmt: skip
    return Flow.model_validate(base | over)


def alert(id: str, ts: float) -> Alert:
    return Alert(
        id=id, ts=ts, detector="portscan", host_mac=A, host_ip="192.168.2.3",
        severity=0.9, confidence=0.8, evidence={"unique_ports_10s": 412.0}, technique="T1046",
    )  # fmt: skip


def incident(alerts: list[str], **over: object) -> Incident:
    base: dict[str, object] = {
        "id": "i1", "host_mac": A, "start_ts": 1.0, "end_ts": 2.0, "alerts": alerts,
        "chain": ["T1046"], "score": 0.7,
    }  # fmt: skip
    return Incident.model_validate(base | over)


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Storage]:
    storage = Storage(tmp_path / "s.db", clock=lambda: 1000.0)
    yield storage
    storage.close()


def test_open_enables_wal_fk_and_latest_version(db: Storage) -> None:
    """R-STO-001"""
    assert db.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == max(
        v for v, _ in load_migrations()
    )
    assert db.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_reopen_is_idempotent_and_keeps_data(tmp_path: Path) -> None:
    first = Storage(tmp_path / "s.db")
    first.insert_flows([flow(1.0)])
    first.close()
    second = Storage(tmp_path / "s.db")
    assert len(second.flows_for_host(A, 0, 10)) == 1
    second.close()


def test_failed_migration_rolls_back_schema_and_version() -> None:
    conn = sqlite3.connect(":memory:", isolation_level=None)
    migrate(conn, [(1, "CREATE TABLE a(x);")])
    with pytest.raises(sqlite3.Error):
        migrate(conn, [(1, "CREATE TABLE a(x);"), (2, "CREATE TABLE b(x); NOT SQL;")])
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    assert conn.execute("SELECT name FROM sqlite_master WHERE name='b'").fetchone() is None
    conn.close()


def test_database_newer_than_code_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "s.db"
    Storage(path).close()
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version=999")
    conn.close()
    with pytest.raises(StorageError):
        Storage(path)


def test_flows_roundtrip_ordered_by_time_and_match_either_direction(db: Storage) -> None:
    db.insert_flows([flow(3.0), flow(1.0), flow(2.0, src=B, dst=A), flow(9.0, src=B, dst=B)])
    got = db.flows_for_host(A, 0.0, 5.0)
    assert [f.ts for f in got] == [1.0, 2.0, 3.0]
    assert got[0] == flow(1.0)


def test_flow_host_lookup_uses_indexes_not_a_scan(db: Storage) -> None:
    rows = db.conn.execute("EXPLAIN QUERY PLAN " + FLOWS_FOR_HOST_SQL, (A, A, 0.0, 5.0))
    plan = " ".join(r[3] for r in rows)
    assert "SCAN flow" not in plan


def test_alert_roundtrip(db: Storage) -> None:
    db.insert_alert(alert("a1", 5.0))
    db.insert_alert(alert("a2", 1.0))
    assert db.alerts_since(2.0) == [alert("a1", 5.0)]


def test_incident_save_get_and_update_replaces_links(db: Storage) -> None:
    for i in ("a1", "a2", "a3"):
        db.insert_alert(alert(i, {"a1": 1.0, "a2": 2.0, "a3": 3.0}[i]))
    db.save_incident(incident(["a2", "a1"]))
    assert db.get_incident("i1") == incident(["a1", "a2"])
    db.save_incident(incident(["a3"], status="explained", summary="x"))
    got = db.get_incident("i1")
    assert got is not None
    assert (got.alerts, got.status, got.summary) == (["a3"], "explained", "x")
    assert db.get_incident("nope") is None


def test_incident_with_unknown_alert_is_rejected_and_nothing_is_saved(db: Storage) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db.save_incident(incident(["missing"]))
    assert db.get_incident("i1") is None


def test_audit_is_append_only_and_uses_injected_clock(db: Storage) -> None:
    """R-STO-003"""
    db.audit("cli", "mode_set", "strict", {"from": "standard"})
    [entry] = db.audit_entries()
    assert (entry.ts, entry.actor, entry.detail) == (1000.0, "cli", {"from": "standard"})
    with pytest.raises(sqlite3.IntegrityError):
        db.conn.execute("UPDATE audit_log SET actor='x'")
    with pytest.raises(sqlite3.IntegrityError):
        db.conn.execute("DELETE FROM audit_log")


def test_prune_removes_only_data_older_than_cutoffs_and_never_audit(db: Storage) -> None:
    """R-STO-002"""
    db.insert_flows([flow(1.0), flow(10.0)])
    db.insert_alert(alert("old", 1.0))
    db.insert_alert(alert("new", 10.0))
    db.save_incident(incident(["old"], id="iold", end_ts=1.0))
    db.save_incident(incident(["new"], id="inew", end_ts=10.0))
    db.audit("cli", "x", "y")
    counts = db.prune(flows_before=5.0, alerts_before=5.0)
    assert counts == {"flows": 1, "alerts": 1, "incidents": 1}
    assert [f.ts for f in db.flows_for_host(A, 0, 100)] == [10.0]
    assert [a.id for a in db.alerts_since(0)] == ["new"]
    assert db.get_incident("iold") is None
    assert db.get_incident("inew") is not None
    assert len(db.audit_entries()) == 1


@pytest.mark.security
def test_hostile_strings_are_stored_as_data(db: Storage) -> None:
    """All SQL is parameterised: injection text round-trips and tables survive."""
    evil = "x'); DROP TABLE flows;--"
    db.insert_flows([flow(1.0, dns_query=evil, dns_qtype=evil)])
    db.audit(evil, evil, evil, {evil: evil})
    [got] = db.flows_for_host(A, 0, 10)
    assert got.dns_query == evil
    assert db.audit_entries()[0].detail == {evil: evil}
    assert db.flows_for_host(evil, 0, 10) == []


def test_inserting_the_same_alert_twice_is_idempotent(db: Storage) -> None:
    db.insert_alert(alert("a1", 5.0))
    db.insert_alert(alert("a1", 5.0))
    assert len(db.alerts_since(0)) == 1
