"""SQLite storage: WAL, numbered migrations, flows/alerts/incidents/audit, retention.

One connection per Storage; the caller serialises access.
"""

import json
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

from sentinel.contracts.models import Alert, AuditEntry, Flow, Incident

# Two indexed lookups unioned: a host is either side of a flow.
FLOWS_FOR_HOST_SQL = """
SELECT * FROM flow WHERE (src_mac = ? OR dst_mac = ?) AND ts >= ? AND ts < ? ORDER BY ts, id
"""
_FLOW_COLUMNS = list(Flow.model_fields)


class StorageError(Exception):
    pass


def load_migrations() -> list[tuple[int, str]]:
    """Packaged migrations as (version, sql), where the file name is `<version>_<name>.sql`."""
    found = resources.files("sentinel.storage") / "migrations"
    return sorted(
        (int(f.name.split("_", 1)[0]), f.read_text())
        for f in found.iterdir()
        if f.name.endswith(".sql")
    )


def migrate(conn: sqlite3.Connection, migrations: list[tuple[int, str]]) -> None:
    """Apply pending migrations, each atomically with its version bump. conn must be autocommit."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    newest = max((v for v, _ in migrations), default=0)
    if current > newest:
        raise StorageError(f"database schema v{current} is newer than this code (v{newest})")
    for version, sql in sorted(migrations):
        if version <= current:
            continue
        try:
            conn.executescript(f"BEGIN;\n{sql}\nPRAGMA user_version={version};\nCOMMIT;")
        except sqlite3.Error:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise


class Storage:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        try:
            migrate(self.conn, load_migrations())
        except BaseException:
            self.conn.close()
            raise

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def _tx(self) -> Iterator[None]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    def insert_flows(self, flows: Iterable[Flow]) -> None:
        cols = ", ".join(_FLOW_COLUMNS)
        marks = ", ".join(f":{c}" for c in _FLOW_COLUMNS)
        with self._tx():
            self.conn.executemany(
                f"INSERT INTO flow ({cols}) VALUES ({marks})",  # noqa: S608 - names from the model
                (f.model_dump() for f in flows),
            )

    def flows_for_host(self, mac: str, start: float, end: float) -> list[Flow]:
        rows = self.conn.execute(FLOWS_FOR_HOST_SQL, (mac, mac, start, end))
        return [Flow.model_validate({c: r[c] for c in _FLOW_COLUMNS}) for r in rows]

    def insert_alert(self, a: Alert) -> None:
        self.conn.execute(
            "INSERT INTO alert (id, ts, detector, host_mac, host_ip, severity, confidence,"
            " evidence_json, technique) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (a.id, a.ts, a.detector, a.host_mac, a.host_ip, a.severity, a.confidence,
             json.dumps(a.evidence), a.technique),
        )  # fmt: skip

    def alerts_since(self, ts: float) -> list[Alert]:
        rows = self.conn.execute("SELECT * FROM alert WHERE ts >= ? ORDER BY ts, id", (ts,))
        return [
            Alert.model_validate(
                {**{k: r[k] for k in r.keys() if k != "evidence_json"},  # noqa: SIM118
                 "evidence": json.loads(r["evidence_json"])}
            )
            for r in rows
        ]  # fmt: skip

    def save_incident(self, i: Incident) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO incident (id, host_mac, start_ts, end_ts, chain_json, score, summary,"
                " status) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET"
                " host_mac=excluded.host_mac, start_ts=excluded.start_ts, end_ts=excluded.end_ts,"
                " chain_json=excluded.chain_json, score=excluded.score, summary=excluded.summary,"
                " status=excluded.status",
                (i.id, i.host_mac, i.start_ts, i.end_ts, json.dumps(i.chain), i.score, i.summary,
                 i.status),
            )  # fmt: skip
            self.conn.execute("DELETE FROM incident_alert WHERE incident_id = ?", (i.id,))
            self.conn.executemany(
                "INSERT INTO incident_alert (incident_id, alert_id) VALUES (?, ?)",
                [(i.id, alert_id) for alert_id in i.alerts],
            )

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self.conn.execute("SELECT * FROM incident WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            return None
        alerts = self.conn.execute(
            "SELECT a.id FROM incident_alert l JOIN alert a ON a.id = l.alert_id"
            " WHERE l.incident_id = ? ORDER BY a.ts, a.id",
            (incident_id,),
        )
        return Incident.model_validate(
            {
                "id": row["id"], "host_mac": row["host_mac"], "start_ts": row["start_ts"],
                "end_ts": row["end_ts"], "alerts": [a["id"] for a in alerts],
                "chain": json.loads(row["chain_json"]), "score": row["score"],
                "summary": row["summary"], "status": row["status"],
            }
        )  # fmt: skip

    def audit(
        self, actor: str, action: str, target: str, detail: dict[str, object] | None = None
    ) -> None:
        self.conn.execute(
            "INSERT INTO audit_log (ts, actor, action, target, detail_json) VALUES (?, ?, ?, ?, ?)",
            (self._clock(), actor, action, target, json.dumps(detail or {})),
        )

    def audit_entries(self) -> list[AuditEntry]:
        rows = self.conn.execute("SELECT * FROM audit_log ORDER BY id")
        return [
            AuditEntry(
                id=r["id"], ts=r["ts"], actor=r["actor"], action=r["action"], target=r["target"],
                detail=json.loads(r["detail_json"]),
            )
            for r in rows
        ]  # fmt: skip

    def prune(self, *, flows_before: float, alerts_before: float) -> dict[str, int]:
        """Delete old data, return counts. Incidents go with alerts; audit_log is never pruned."""
        with self._tx():
            incidents = self.conn.execute("DELETE FROM incident WHERE end_ts < ?", (alerts_before,))
            alerts = self.conn.execute("DELETE FROM alert WHERE ts < ?", (alerts_before,))
            flows = self.conn.execute("DELETE FROM flow WHERE ts < ?", (flows_before,))
        return {"flows": flows.rowcount, "alerts": alerts.rowcount, "incidents": incidents.rowcount}
