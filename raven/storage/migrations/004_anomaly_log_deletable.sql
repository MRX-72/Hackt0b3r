-- The History view lets the user delete specific entries (each deletion is written to audit_log).
-- Rows still cannot be edited, and retention still never touches this table.
DROP TRIGGER anomaly_log_no_delete;
