"""SQLite storage: WAL, numbered migrations, flows/alerts/incidents/audit, retention.

One connection per Storage; the caller serialises access.
"""

import json
import os
import sqlite3
import stat
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from raven.contracts.models import (
    Alert,
    AnomalyRecord,
    AuditEntry,
    Delivery,
    DeliveryRecord,
    DeviceRecord,
    Flow,
    HistoryQuery,
    Incident,
)
from raven.contracts.severity import severity_label
from raven.contracts.text import terminal_safe

# Two indexed lookups unioned: a host is either side of a flow.
FLOWS_FOR_HOST_SQL = """
SELECT * FROM flow WHERE (src_mac = ? OR dst_mac = ?) AND ts >= ? AND ts < ? ORDER BY ts, id
"""
_FLOW_COLUMNS = list(Flow.model_fields)


class StorageError(Exception):
    pass


def load_migrations() -> list[tuple[int, str]]:
    """Packaged migrations as (version, sql), where the file name is `<version>_<name>.sql`."""
    found = resources.files("raven.storage") / "migrations"
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


@dataclass
class DeviceSeen:
    """Traffic one device showed since the last flush (deltas), merged into the inventory."""

    mac: str
    ips: set[str] = field(default_factory=set)
    first: float = 0.0
    last: float = 0.0
    packets: int = 0
    bytes_out: int = 0
    bytes_in: int = 0


_LABEL_BY_RANK = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_DEVICES_SQL = """
SELECT d.mac, d.first_seen, d.last_seen, d.packets, d.bytes_out, d.bytes_in,
       d.type_label_admin AS name,
       (SELECT group_concat(ip, ',') FROM
          (SELECT ip FROM device_ip WHERE mac = d.mac ORDER BY last_seen DESC LIMIT 8)) AS ips,
       COALESCE(a.n, 0) AS alerts, a.last_ts, a.rank
FROM device d LEFT JOIN (
  SELECT host_mac, COUNT(*) AS n, MAX(ts) AS last_ts,
         MIN(CASE label WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END)
           AS rank
  FROM anomaly_log GROUP BY host_mac) a ON a.host_mac = d.mac
"""


def _make_private(path: Path) -> None:
    """The history holds addresses, DNS names and evidence: owner-only, never the umask default.

    A new database is created 0600 (SQLite gives its -wal and -shm files the same mode). Existing
    files of ours (database, -wal, -shm) are tightened, but only a single-link regular file owned
    by this user or the sudo user is touched, and never through a symlink.
    """
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
    except FileExistsError:
        if path.is_symlink() and not path.exists():
            raise StorageError(f"{path} is a dangling symlink; not creating through it") from None
    try:
        owners = {os.geteuid(), int(os.environ.get("SUDO_UID", "-1"))}
    except ValueError:
        owners = {os.geteuid()}
    for suffix in ("", "-wal", "-shm"):
        _tighten(path.with_name(path.name + suffix), owners)


def _tighten(path: Path, owners: set[int]) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:  # missing, or a symlink: leave it alone
        return
    try:
        info = os.fstat(fd)
        loose = info.st_mode & 0o077
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in owners and loose:
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _give_away(path: Path, uid: int, gid: int) -> None:
    """chown one of our own files (or the folder we created) without being steered elsewhere.

    The folder belongs to the user, so they could plant a symlink or hard link there. The folder
    is opened without following links, the entry is opened relative to it, and only a
    single-link regular file (or directory) owned by root or by that user is touched.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        parent = os.open(path.parent, flags | os.O_DIRECTORY)
        try:
            fd = os.open(path.name, flags, dir_fd=parent)
        finally:
            os.close(parent)
    except OSError:  # missing, or a symlink: leave it alone
        return
    try:
        info = os.fstat(fd)
        plain = stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        if (plain or stat.S_ISDIR(info.st_mode)) and info.st_uid in (0, uid):
            os.fchown(fd, uid, gid)
    finally:
        os.close(fd)


class Storage:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._made_folder = not path.parent.exists()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._path = path
        _make_private(path)
        # One thread uses a Storage at a time; the capture thread may be joined and closed by main.
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        try:  # any failure (not a database, a bad migration) must not leak the handle
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            migrate(self.conn, load_migrations())
        except BaseException:
            self.conn.close()
            raise
        self._hand_back()

    def close(self) -> None:
        self.conn.close()
        self._hand_back()

    def _hand_back(self) -> None:
        """Under `sudo` the files are created by root; give them to the invoking user so a later
        run without sudo (the web console, `history`) can still open them."""
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if os.geteuid() != 0 or not uid or not gid:
            return
        targets = [self._path.with_name(self._path.name + s) for s in ("", "-wal", "-shm")]
        if self._made_folder:  # never touch a folder that was already there
            targets.append(self._path.parent)
        for target in targets:
            _give_away(target, int(uid), int(gid))

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
        allowed = {"alert", "flow", "incident", "device", "notification_delivery"}
        if table not in allowed:
            raise ValueError(table)
        return int(self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608

    def incident_status_counts(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT status, COUNT(*) AS n FROM incident GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    def log_delivery(
        self, d: Delivery, incident_id: str, headline: str | None = None, label: str | None = None
    ) -> None:
        error = None if d.status == "sent" else d.detail
        self.conn.execute(
            "INSERT INTO notification_delivery (ts, channel, incident_id, status, error,"
            " headline, label) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self._clock(), d.channel, incident_id, d.status, error, headline, label),
        )

    def log_anomaly(self, record: AnomalyRecord) -> int:
        """Append to the permanent history; returns the row id (the old one if already logged)."""
        cursor = self.conn.execute(
            "INSERT OR IGNORE INTO anomaly_log (ts, logged_at, source, detector, technique,"
            " severity,"
            " confidence, label, score, host_mac, host_ip, target_ip, headline, what_happened,"
            " likely_cause, action, chain_json, incident_id, evidence_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (record.ts, record.logged_at, record.source, record.detector, record.technique,
             record.severity, record.confidence, record.label, record.score, record.host_mac,
             record.host_ip, record.target_ip, record.headline, record.what_happened,
             record.likely_cause, record.action, json.dumps(record.chain), record.incident_id,
             json.dumps(record.evidence)),
        )  # fmt: skip
        if cursor.rowcount:
            assert cursor.lastrowid is not None  # noqa: S101 - an INSERT always has a row id
            return cursor.lastrowid
        row = self.conn.execute(
            "SELECT id FROM anomaly_log WHERE source = ? AND detector = ? AND host_mac = ?"
            " AND ts = ? AND COALESCE(target_ip, '') = ?",
            (record.source, record.detector, record.host_mac, record.ts, record.target_ip or ""),
        ).fetchone()
        return int(row["id"])

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

    def delete_anomalies(self, ids: Iterable[int], actor: str = "ui") -> int:
        """Delete the chosen history entries; returns how many existed. The deletion is audited."""
        chosen = sorted(set(ids))
        if not chosen:
            return 0
        marks = ",".join("?" * len(chosen))
        with self._tx():
            deleted = self.conn.execute(
                f"DELETE FROM anomaly_log WHERE id IN ({marks})",  # noqa: S608 - only "?" marks
                chosen,
            ).rowcount
            self.audit(actor, "history_delete", f"{deleted} entries", {"ids": chosen})
        return deleted

    # ---- notifications ------------------------------------------------------------------
    def deliveries(
        self, *, channel: str | None = None, status: str | None = None, limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, list[DeliveryRecord]]:  # fmt: skip
        """Stored notification attempts, newest first, with the incident they were about."""
        where, args = [], []
        for column, value in (("d.channel", channel), ("d.status", status)):
            if value is not None:
                where.append(f"{column} = ?")
                args.append(value)
        clause = f" WHERE {' AND '.join(where)}" if where else ""  # fixed fragments only
        count_sql = "SELECT COUNT(*) FROM notification_delivery d" + clause  # noqa: S608
        total = self.conn.execute(count_sql, args).fetchone()[0]
        list_sql = (
            "SELECT d.id, d.ts, d.channel, d.status, d.error, d.incident_id,"  # noqa: S608 - clause holds only fixed column names and ? marks
            " COALESCE(d.headline, i.summary) AS headline, d.label AS stored_label,"
            " i.score FROM notification_delivery d LEFT JOIN incident i ON i.id = d.incident_id"
            + clause
            + " ORDER BY d.ts DESC, d.id DESC LIMIT ? OFFSET ?"
        )
        rows = self.conn.execute(list_sql, [*args, limit, offset])
        return total, [self._delivery(r) for r in rows]

    @staticmethod
    def _delivery(row: sqlite3.Row) -> DeliveryRecord:
        score = row["score"]
        label = row["stored_label"] or (None if score is None else severity_label(score).upper())
        return DeliveryRecord.model_validate(
            {**{k: row[k] for k in ("id", "ts", "channel", "status", "error", "incident_id",
                                    "headline")}, "label": label}
        )  # fmt: skip

    def delivery_counts(self, since: float) -> dict[str, dict[str, int]]:
        """{channel: {status: n}} for attempts at or after `since`."""
        out: dict[str, dict[str, int]] = {}
        for r in self.conn.execute(
            "SELECT channel, status, COUNT(*) AS n FROM notification_delivery WHERE ts >= ?"
            " GROUP BY channel, status", (since,),
        ):  # fmt: skip
            out.setdefault(r["channel"], {})[r["status"]] = r["n"]
        return out

    # ---- devices ------------------------------------------------------------------------
    def upsert_devices(self, seen: Iterable[DeviceSeen]) -> None:
        with self._tx():
            for d in seen:
                self.conn.execute(
                    "INSERT INTO device (mac, first_seen, last_seen, packets, bytes_out, bytes_in)"
                    " VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(mac) DO UPDATE SET"
                    " first_seen = MIN(first_seen, excluded.first_seen),"
                    " last_seen = MAX(last_seen, excluded.last_seen),"
                    " packets = packets + excluded.packets,"
                    " bytes_out = bytes_out + excluded.bytes_out,"
                    " bytes_in = bytes_in + excluded.bytes_in",
                    (d.mac, d.first, d.last, d.packets, d.bytes_out, d.bytes_in),
                )
                for ip in d.ips:
                    self.conn.execute(
                        "INSERT INTO device_ip (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)"
                        " ON CONFLICT(mac, ip) DO UPDATE SET"
                        " first_seen = MIN(first_seen, excluded.first_seen),"
                        " last_seen = MAX(last_seen, excluded.last_seen)",
                        (d.mac, ip, d.first, d.last),
                    )

    @staticmethod
    def _device(row: sqlite3.Row) -> DeviceRecord:
        rank = row["rank"]
        return DeviceRecord.model_validate(
            {**{k: row[k] for k in ("mac", "name", "first_seen", "last_seen", "packets",
                                    "bytes_out", "bytes_in", "alerts")},
             "ips": (row["ips"] or "").split(",") if row["ips"] else [],
             "worst_label": None if rank is None else _LABEL_BY_RANK[rank],
             "last_alert_ts": row["last_ts"]}
        )  # fmt: skip

    def devices(self, limit: int = 500) -> list[DeviceRecord]:
        rows = self.conn.execute(_DEVICES_SQL + " ORDER BY d.last_seen DESC LIMIT ?", (limit,))
        return [self._device(r) for r in rows]

    def device(self, mac: str) -> DeviceRecord | None:
        row = self.conn.execute(_DEVICES_SQL + " WHERE d.mac = ?", (mac,)).fetchone()
        return None if row is None else self._device(row)

    def set_device_name(self, mac: str, name: str, actor: str = "ui") -> bool:
        """Set (or, with an empty name, clear) the admin label. False if the device is unknown."""
        value = terminal_safe(name.strip(), 40) or None
        with self._tx():
            changed = self.conn.execute(
                "UPDATE device SET type_label_admin = ? WHERE mac = ?", (value, mac)
            ).rowcount
            if changed:
                self.audit(actor, "device_label", mac, {"name": value})
        return bool(changed)

    def anomalies_of_device(self, mac: str, limit: int = 10) -> list[AnomalyRecord]:
        rows = self.conn.execute(
            "SELECT * FROM anomaly_log WHERE host_mac = ? ORDER BY ts DESC, id DESC LIMIT ?",
            (mac, limit),
        )
        return [self._anomaly(r) for r in rows]

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
