-- What the notification said and how severe it was when it was sent. The incident's own summary
-- changes as the incident grows, so it cannot describe an old delivery.
ALTER TABLE notification_delivery ADD COLUMN headline TEXT;
ALTER TABLE notification_delivery ADD COLUMN label TEXT;
