-- The same alert must never be logged twice (two capturing processes did exactly that).
-- Keep the oldest copy of any existing duplicate, then forbid new ones.
DELETE FROM anomaly_log WHERE id NOT IN (
  SELECT MIN(id) FROM anomaly_log GROUP BY source, detector, host_mac, ts, COALESCE(target_ip, '')
);
CREATE UNIQUE INDEX anomaly_log_once ON anomaly_log(source, detector, host_mac, ts, COALESCE(target_ip, ''));
