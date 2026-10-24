-- Alerts name their main target host (validated IP) so notifications can say who was hit.
ALTER TABLE alert ADD COLUMN target_ip TEXT;
