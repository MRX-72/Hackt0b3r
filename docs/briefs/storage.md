# Brief: storage (Stage 1, component 1)

**Purpose:** one SQLite file (WAL) holding flows, alerts, incidents and the append-only audit log, with numbered migrations and retention.

**Inputs/outputs:** contracts `Flow`, `Alert`, `Incident`, `AuditEntry` in and out. API: `Storage(path, clock)`, `insert_flows`, `flows_for_host`, `insert_alert`, `alerts_since`, `save_incident`, `get_incident`, `audit`, `audit_entries`, `prune`, `close`; `migrate(conn, migrations)`.
Schema is diagram 06 (this commit adds `dns_query`, `dns_qtype` to FLOW). Tables for devices, feature snapshots, enforcement rules, feedback and notifications exist from migration 1 but get accessors when their components land.

**Invariants:**
- journal_mode=WAL, foreign_keys=ON; `user_version` equals the last applied migration.
- A migration is atomic: failure leaves schema and version unchanged. A DB newer than the code is refused.
- All SQL is parameterised; network-derived strings are data only.
- `audit_log` rejects UPDATE and DELETE (trigger). `prune` never touches it.
- Host lookups on flows use an index, not a table scan.
- `save_incident` is atomic and replaces the incident's alert links.

**Failure modes:** unknown alert id in an incident -> `sqlite3.IntegrityError`; invalid rows on read -> pydantic `ValidationError` (loud); newer schema -> `StorageError`.

**Requirements:** R-STO-001, R-STO-002 (flows/alerts/incidents only; pcap ring buffer is the daemon's), R-STO-003, R-DET-009 (shapes), R-PRC-001.

**Tests (written before the code):** `tests/test_storage.py` — migrate/WAL/version, idempotent reopen, rollback on bad migration, newer-DB refusal, flow and alert roundtrip, index use, incident upsert + links + FK, audit append-only + clock, prune boundaries leave audit alone, hostile-string roundtrip (security group).

**Out of scope:** device/inventory accessors, feature snapshots, config wiring of retention days (config component), async access (single connection, caller serialises).
