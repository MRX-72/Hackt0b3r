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

from sentinel.contracts.models import (
    Alert,
    AnomalyRecord,
    AuditEntry,
    Delivery,
    Flow,
    HistoryQuery,
    Incident,
)

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
        # One thread uses a Storage at a time; the capture thread may be joined and closed by main.
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
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
            " evidence_json, technique, target_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO NOTHING",  # replaying a capture twice is idempotent
            (a.id, a.ts, a.detector, a.host_mac, a.host_ip, a.severity, a.confidence,
             json.dumps(a.evidence), a.technique, a.target_ip),
        )  # fmt: skip

    @staticmethod
    def _alert(row: sqlite3.Row) -> Alert:
        fields = {k: row[k] for k in row.keys() if k != "evidence_json"}  # noqa: SIM118
        return Alert.model_validate({**fields, "evidence": json.loads(row["evidence_json"])})

    def alerts_since(self, ts: float) -> list[Alert]:
        rows = self.conn.execute("SELECT * FROM alert WHERE ts >= ? ORDER BY ts, id", (ts,))
        return [self._alert(r) for r in rows]

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

    def alerts_of_incident(self, incident_id: str) -> list[Alert]:
        rows = self.conn.execute(
            "SELECT a.* FROM incident_alert l JOIN alert a ON a.id = l.alert_id"
            " WHERE l.incident_id = ? ORDER BY a.ts, a.id",
            (incident_id,),
        )
        return [self._alert(r) for r in rows]

    def recent_incidents(
        self,
        limit: int,
        *,
        since: float | None = None,
        min_score: float = 0.0,
        include_closed: bool = False,
    ) -> list[Incident]:
        closed = "" if include_closed else " AND status NOT IN ('dismissed', 'resolved')"
        rows = self.conn.execute(
            f"SELECT id FROM incident WHERE end_ts >= ? AND score >= ?{closed}"  # noqa: S608
            " ORDER BY end_ts DESC LIMIT ?",
            (since if since is not None else -1.0, min_score, limit),
        )
        return [i for r in rows if (i := self.get_incident(r["id"])) is not None]

    def match_incident_ids(self, prefix: str) -> list[str]:
        """Ids equal to, or starting with, `prefix` (exact match wins)."""
        escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = self.conn.execute(
            "SELECT id FROM incident WHERE id = ? OR id LIKE ? ESCAPE '\\' ORDER BY end_ts DESC",
            (prefix, escaped + "%"),
        )
        found = [r["id"] for r in rows]
        return [prefix] if prefix in found else found

    def set_incident_status(self, incident_id: str, status: str, actor: str) -> None:
        with self._tx():
            done = self.conn.execute(
                "UPDATE incident SET status = ? WHERE id = ?", (status, incident_id)
            )
            if done.rowcount != 1:
                raise KeyError(incident_id)
            self.audit(actor, "incident_status", incident_id, {"status": status})

    def count_rows(self, table: str) -> int:
        allowed = {"alert", "flow", "incident"}
        if table not in allowed:
            raise ValueError(table)
        return int(self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608

    def incident_status_counts(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT status, COUNT(*) AS n FROM incident GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    def log_delivery(self, d: Delivery, incident_id: str) -> None:
        error = None if d.status == "sent" else d.detail
        self.conn.execute(
            "INSERT INTO notification_delivery (ts, channel, incident_id, status, error)"
            " VALUES (?, ?, ?, ?, ?)",
            (self._clock(), d.channel, incident_id, d.status, error),
        )

    def log_anomaly(self, record: AnomalyRecord) -> int:
        """Append to the permanent history; returns the new row id."""
        cursor = self.conn.execute(
            "INSERT INTO anomaly_log (ts, logged_at, source, detector, technique, severity,"
            " confidence, label, score, host_mac, host_ip, target_ip, headline, what_happened,"
            " likely_cause, action, chain_json, incident_id, evidence_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (record.ts, record.logged_at, record.source, record.detector, record.technique,
             record.severity, record.confidence, record.label, record.score, record.host_mac,
             record.host_ip, record.target_ip, record.headline, record.what_happened,
             record.likely_cause, record.action, json.dumps(record.chain), record.incident_id,
             json.dumps(record.evidence)),
        )  # fmt: skip
        assert cursor.lastrowid is not None  # noqa: S101 - an INSERT always has a row id
        return cursor.lastrowid

    @staticmethod
    def _anomaly(row: sqlite3.Row) -> AnomalyRecord:
        skip = ("chain_json", "evidence_json")
        fields = {k: row[k] for k in row.keys() if k not in skip}  # noqa: SIM118
        return AnomalyRecord.model_validate(
            {**fields, "chain": json.loads(row["chain_json"]),
             "evidence": json.loads(row["evidence_json"])}
        )  # fmt: skip

    def anomalies(self, query: HistoryQuery) -> tuple[int, list[AnomalyRecord]]:
        """Newest first, with the total number of matches. `text` searches the visible columns."""
        where, args = self._anomaly_filter(query)
        total_sql = "SELECT COUNT(*) FROM anomaly_log WHERE " + where  # noqa: S608 - fixed fragments
        order = " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        rows_sql = "SELECT * FROM anomaly_log WHERE " + where + order  # noqa: S608 - fixed fragments
        total = self.conn.execute(total_sql, args).fetchone()[0]
        rows = self.conn.execute(rows_sql, [*args, query.limit, query.offset])
        return total, [self._anomaly(r) for r in rows]

    @staticmethod
    def _anomaly_filter(query: HistoryQuery) -> tuple[str, list[object]]:
        """A WHERE clause made only of fixed fragments; every value travels as a parameter."""
        where: list[str] = ["1 = 1"]
        args: list[object] = []
        for column, value in (("label", query.label), ("source", query.source)):
            if value:
                where.append(f"{column} = ?")
                args.append(value)
        if query.since is not None:
            where.append("ts >= ?")
            args.append(query.since)
        if query.until is not None:
            where.append("ts < ?")
            args.append(query.until)
        if query.text:
            escaped = query.text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            columns = ("headline", "detector", "technique", "host_ip", "target_ip", "incident_id")
            where.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in columns) + ")")
            args += [f"%{escaped}%"] * len(columns)
        return " AND ".join(where), args

    def anomaly(self, anomaly_id: int) -> AnomalyRecord | None:
        row = self.conn.execute("SELECT * FROM anomaly_log WHERE id = ?", (anomaly_id,)).fetchone()
        return None if row is None else self._anomaly(row)

    def anomaly_label_counts(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT label, COUNT(*) AS n FROM anomaly_log GROUP BY label")
        return {r["label"]: r["n"] for r in rows}

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
