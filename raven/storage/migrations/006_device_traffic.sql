-- Device inventory gains traffic totals (the table itself came with the first schema).
ALTER TABLE device ADD COLUMN packets INTEGER NOT NULL DEFAULT 0;
ALTER TABLE device ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0;
ALTER TABLE device ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0;
CREATE INDEX notification_delivery_ts ON notification_delivery(ts);
