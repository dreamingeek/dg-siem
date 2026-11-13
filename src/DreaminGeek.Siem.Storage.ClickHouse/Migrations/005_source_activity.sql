-- Hourly activity per source (Administration > Health): what each tenant's hosts send, per dataset, by the hour the
-- server received it (ingest_time, so a device with a wrong clock still counts as sending). Kept up by a materialized
-- view on every insert, so health checks read a few thousand rows instead of scanning events.
-- "host" is host.name, or the sending device's address (observer.ip) when the log names no host.
CREATE TABLE IF NOT EXISTS {db}.source_activity
(
    tenant_id     LowCardinality(String),
    event_dataset LowCardinality(String),
    host          LowCardinality(String),
    hour          DateTime('UTC'),
    events        SimpleAggregateFunction(sum, UInt64),
    bytes         SimpleAggregateFunction(sum, UInt64),
    last_seen     SimpleAggregateFunction(max, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, event_dataset, host, hour)
TTL hour + INTERVAL 35 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.source_activity_mv TO {db}.source_activity AS
SELECT
    tenant_id,
    event_dataset,
    if(host_name != '', host_name, observer_ip) AS host,
    toStartOfHour(ingest_time) AS hour,
    count() AS events,
    sum(length(raw)) AS bytes,
    max(ingest_time) AS last_seen
FROM {db}.events
GROUP BY tenant_id, event_dataset, host, hour;

-- Backfill the last 8 days, so quiet-source checks have a baseline from the first day. Migrations run before the
-- server accepts events, so nothing is counted twice.
INSERT INTO {db}.source_activity
SELECT
    tenant_id,
    event_dataset,
    if(host_name != '', host_name, observer_ip) AS host,
    toStartOfHour(ingest_time) AS hour,
    count() AS events,
    sum(length(raw)) AS bytes,
    max(ingest_time) AS last_seen
FROM {db}.events
WHERE ingest_time >= now() - INTERVAL 8 DAY
GROUP BY tenant_id, event_dataset, host, hour;
