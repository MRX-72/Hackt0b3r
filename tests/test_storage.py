import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinel.contracts.models import Alert, Flow, Incident
from sentinel.storage.db import (
    FLOWS_FOR_HOST_SQL,
    Storage,
    StorageError,
    _give_away,
    load_migrations,
    migrate,
)
from tests.test_ui import record as anomaly

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


def test_upgrading_a_v1_database_keeps_alerts_and_adds_target_column(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path, isolation_level=None)
    migrate(conn, load_migrations()[:1])
    conn.execute(
        "INSERT INTO alert VALUES"
        " ('old', 1.0, 'portscan', ?, '192.168.2.3', 0.9, 0.8, '{}', 'T1046')",
        (A,),
    )
    conn.close()
    upgraded = Storage(path)
    [got] = upgraded.alerts_since(0)
    assert (got.id, got.target_ip) == ("old", None)
    upgraded.insert_alert(alert("new", 2.0).model_copy(update={"target_ip": "192.168.2.2"}))
    assert [a.target_ip for a in upgraded.alerts_since(0)] == [None, "192.168.2.2"]
    upgraded.close()


def test_alerts_of_incident_are_ordered_by_time(db: Storage) -> None:
    db.insert_alert(alert("late", 9.0))
    db.insert_alert(alert("early", 1.0))
    db.save_incident(incident(["late", "early"]))
    assert [a.id for a in db.alerts_of_incident("i1")] == ["early", "late"]


def test_a_missing_data_folder_is_created_privately_and_the_data_persists(tmp_path: Path) -> None:
    path = tmp_path / "new" / "deeper" / "s.db"
    first = Storage(path)
    first.log_anomaly(anomaly())
    first.close()
    assert path.parent.stat().st_mode & 0o777 == 0o700
    again = Storage(path)
    assert again.anomaly_label_counts() == {"CRITICAL": 1}
    again.close()


def test_under_sudo_the_files_are_handed_back_to_the_invoking_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned: list[tuple[int, int, int]] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda fd, u, g: owned.append((os.fstat(fd).st_ino, u, g)))
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    folder = tmp_path / "fresh"
    store = Storage(folder / "s.db")
    store.close()
    inodes = {ino for ino, uid, gid in owned if (uid, gid) == (501, 20)}
    assert (folder / "s.db").stat().st_ino in inodes
    assert folder.stat().st_ino in inodes  # created by us
    owned.clear()
    Storage(folder / "s.db").close()  # existing folder is not ours to change
    assert folder.stat().st_ino not in {ino for ino, _, _ in owned}
    monkeypatch.setattr(os, "geteuid", lambda: 501)  # not root: nothing to hand back
    owned.clear()
    Storage(folder / "s.db").close()
    assert owned == []


def test_a_planted_symlink_is_never_followed_by_the_handback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "victim"
    victim.write_text("root's file")
    folder = tmp_path / "home"
    folder.mkdir()
    owned: list[int] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda fd, u, g: owned.append(os.fstat(fd).st_ino))
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    store = Storage(folder / "s.db")
    (folder / "s.db-wal").unlink(missing_ok=True)
    (folder / "s.db-wal").symlink_to(victim)  # planted while Sentinel runs as root
    store._hand_back()
    assert owned and victim.stat().st_ino not in owned
    (folder / "s.db-wal").unlink()
    store.close()


def test_a_planted_hard_link_or_foreign_owned_file_is_not_handed_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "home"
    folder.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("x")
    os.link(victim, folder / "s.db-shm")  # two links: not ours
    owned: list[int] = []
    monkeypatch.setattr(os, "fchown", lambda fd, u, g: owned.append(os.fstat(fd).st_ino))
    _give_away(folder / "s.db-shm", 501, 20)
    assert owned == []
    plain = folder / "plain"
    plain.write_text("x")
    _give_away(plain, os.getuid(), 20)  # a single-link file owned by the target user: handed over
    assert owned == [plain.stat().st_ino]
    other = folder / "other"
    other.write_text("x")
    owned.clear()
    _give_away(other, os.getuid() + 1, 20)  # owned by someone else entirely: left alone
    assert owned == []


@pytest.mark.security
def test_the_database_and_its_sidecar_files_are_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "private.db"
    store = Storage(path)
    store.log_anomaly(anomaly())  # makes the -wal and -shm files exist
    modes = {p.name: p.stat().st_mode & 0o777 for p in tmp_path.glob("private.db*")}
    store.close()
    assert modes and set(modes.values()) == {0o600}, modes


@pytest.mark.security
def test_an_existing_loose_database_is_tightened_and_a_symlink_is_not_created_through(
    tmp_path: Path,
) -> None:
    loose = tmp_path / "loose.db"
    sqlite3.connect(loose).close()
    loose.chmod(0o644)
    Storage(loose).close()
    assert loose.stat().st_mode & 0o777 == 0o600
    victim = tmp_path / "victim"
    link = tmp_path / "link.db"
    link.symlink_to(victim)  # dangling: creating "through" it would create the victim
    with pytest.raises(StorageError, match="dangling symlink"):
        Storage(link)
    assert not victim.exists() or victim.stat().st_size == 0


@pytest.mark.security
def test_tightening_never_follows_a_link_and_never_touches_a_directory_or_shared_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "someone_elses_file"
    target.write_text("x")
    target.chmod(0o644)
    link = tmp_path / "linked.db"
    link.symlink_to(target)  # an existing target: sqlite would follow it, we must not chmod it
    Storage(link).close()
    assert target.stat().st_mode & 0o777 == 0o644
    shared = tmp_path / "shared.db"
    sqlite3.connect(shared).close()
    shared.chmod(0o644)
    os.link(shared, tmp_path / "second_name.db")  # two names: not a file we can reason about
    Storage(shared).close()
    assert shared.stat().st_mode & 0o777 == 0o644


@pytest.mark.security
def test_old_sidecar_files_are_tightened_too(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    sqlite3.connect(path).close()
    for suffix in ("", "-wal", "-shm"):
        side = tmp_path / ("old.db" + suffix)
        side.touch(exist_ok=True)
        side.chmod(0o644)
    store = Storage(path)
    modes = {p.name: p.stat().st_mode & 0o777 for p in tmp_path.glob("old.db*")}
    store.close()
    assert set(modes.values()) == {0o600}, modes
