-- The project was renamed (Sentinel -> Raven); the statistical detector's own id follows it.
UPDATE alert SET technique = 'RVN001' WHERE technique = 'SENT001';
UPDATE incident SET chain_json = REPLACE(chain_json, '"SENT001"', '"RVN001"') WHERE chain_json LIKE '%SENT001%';
DROP TRIGGER anomaly_log_no_update;
UPDATE anomaly_log SET technique = 'RVN001' WHERE technique = 'SENT001';
UPDATE anomaly_log SET chain_json = REPLACE(chain_json, '"SENT001"', '"RVN001"') WHERE chain_json LIKE '%SENT001%';
CREATE TRIGGER anomaly_log_no_update BEFORE UPDATE ON anomaly_log
  BEGIN SELECT RAISE(ABORT, 'anomaly_log is append-only'); END;
