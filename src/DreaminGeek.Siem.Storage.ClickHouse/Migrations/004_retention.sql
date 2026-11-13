-- Per-event retention (Administration > Storage). Each event carries the days it's kept, set at ingest from
-- the tenant/dataset rules, and the TTL deletes it when they're up. Rows of different retention share daily
-- partitions, so TTL now deletes rows during merges instead of only dropping whole expired parts.
-- Existing parts keep their 120-day TTL until "Apply to stored events" re-stamps them.
ALTER TABLE {db}.events ADD COLUMN IF NOT EXISTS retention_days UInt16 DEFAULT 120;
ALTER TABLE {db}.events MODIFY TTL toDateTime(timestamp) + toIntervalDay(retention_days) DELETE SETTINGS materialize_ttl_after_modify = 0;
ALTER TABLE {db}.events MODIFY SETTING ttl_only_drop_parts = 0;
