-- Permanent, append-only record of every anomaly Raven reported. Never pruned: the History view
-- reads it, and it must survive retention of the working tables (alert, incident, flow).
CREATE TABLE anomaly_log (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, logged_at REAL NOT NULL, source TEXT NOT NULL,
  detector TEXT NOT NULL, technique TEXT NOT NULL, severity REAL NOT NULL, confidence REAL NOT NULL,
  label TEXT NOT NULL, score REAL NOT NULL, host_mac TEXT NOT NULL, host_ip TEXT NOT NULL,
  target_ip TEXT, headline TEXT NOT NULL, what_happened TEXT NOT NULL, likely_cause TEXT NOT NULL,
  action TEXT NOT NULL, chain_json TEXT NOT NULL, incident_id TEXT NOT NULL,
  evidence_json TEXT NOT NULL
) STRICT;
CREATE INDEX anomaly_log_ts ON anomaly_log(ts);
CREATE INDEX anomaly_log_label_ts ON anomaly_log(label, ts);
CREATE TRIGGER anomaly_log_no_update BEFORE UPDATE ON anomaly_log
  BEGIN SELECT RAISE(ABORT, 'anomaly_log is append-only'); END;
CREATE TRIGGER anomaly_log_no_delete BEFORE DELETE ON anomaly_log
  BEGIN SELECT RAISE(ABORT, 'anomaly_log is append-only'); END;
