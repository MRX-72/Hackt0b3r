-- Schema from docs/diagrams/06-data-model.mmd. STRICT tables; timestamps are unix seconds (REAL).
CREATE TABLE device (
  mac TEXT PRIMARY KEY, vendor TEXT, hostname_sanitized TEXT, type_guess TEXT,
  type_confidence REAL, type_label_admin TEXT, trust TEXT NOT NULL DEFAULT 'unknown',
  first_seen REAL NOT NULL, last_seen REAL NOT NULL
) STRICT;

CREATE TABLE device_ip (
  mac TEXT NOT NULL REFERENCES device(mac) ON DELETE CASCADE, ip TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, PRIMARY KEY (mac, ip)
) STRICT;

-- No FK from flows/alerts to device: events can arrive before inventory has seen the MAC.
CREATE TABLE flow (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, src_mac TEXT NOT NULL, dst_mac TEXT NOT NULL,
  src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, proto TEXT NOT NULL, src_port INTEGER,
  dst_port INTEGER, bytes INTEGER NOT NULL, packets INTEGER NOT NULL, tcp_flags TEXT,
  dns_query TEXT, dns_qtype TEXT
) STRICT;
CREATE INDEX flow_src_ts ON flow(src_mac, ts);
CREATE INDEX flow_dst_ts ON flow(dst_mac, ts);
CREATE INDEX flow_ts ON flow(ts);

CREATE TABLE feature_snapshot (
  host_mac TEXT NOT NULL, ts REAL NOT NULL, window_seconds INTEGER NOT NULL,
  features_json TEXT NOT NULL
) STRICT;
CREATE INDEX feature_snapshot_host_ts ON feature_snapshot(host_mac, ts);

CREATE TABLE alert (
  id TEXT PRIMARY KEY, ts REAL NOT NULL, detector TEXT NOT NULL, host_mac TEXT NOT NULL,
  host_ip TEXT NOT NULL, severity REAL NOT NULL, confidence REAL NOT NULL,
  evidence_json TEXT NOT NULL, technique TEXT NOT NULL
) STRICT;
CREATE INDEX alert_host_ts ON alert(host_mac, ts);
CREATE INDEX alert_ts ON alert(ts);

CREATE TABLE incident (
  id TEXT PRIMARY KEY, host_mac TEXT NOT NULL, start_ts REAL NOT NULL, end_ts REAL NOT NULL,
  chain_json TEXT NOT NULL, score REAL NOT NULL, summary TEXT, status TEXT NOT NULL
) STRICT;
CREATE INDEX incident_end_ts ON incident(end_ts);

CREATE TABLE incident_alert (
  incident_id TEXT NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
  alert_id TEXT NOT NULL REFERENCES alert(id) ON DELETE CASCADE,
  PRIMARY KEY (incident_id, alert_id)
) STRICT;

CREATE TABLE incident_feedback (
  incident_id TEXT NOT NULL REFERENCES incident(id) ON DELETE CASCADE, ts REAL NOT NULL,
  resolution TEXT NOT NULL
) STRICT;

CREATE TABLE enforcement_rule (
  id TEXT PRIMARY KEY, state TEXT NOT NULL, rule_json TEXT NOT NULL, ttl_seconds INTEGER NOT NULL,
  expires_at REAL, created_by TEXT NOT NULL
) STRICT;

CREATE TABLE notification_delivery (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, channel TEXT NOT NULL,
  incident_id TEXT NOT NULL REFERENCES incident(id) ON DELETE CASCADE, status TEXT NOT NULL,
  error TEXT
) STRICT;

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT NOT NULL, detail_json TEXT NOT NULL
) STRICT;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
