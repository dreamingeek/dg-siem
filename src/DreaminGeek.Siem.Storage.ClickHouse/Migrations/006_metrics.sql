-- Metrics (Prometheus scrapes by the agents' Prometheus input). One row per sample. A series is a metric name plus
-- its labels; "series" is a hash of the sorted labels, so a series' samples sit together on disk (rate() reads them
-- in order). Kept retention_days (default 90), like events.
CREATE TABLE IF NOT EXISTS {db}.metrics
(
    tenant_id      LowCardinality(String),
    timestamp      DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    name           LowCardinality(String),
    labels         Map(LowCardinality(String), String),
    series         UInt64 MATERIALIZED cityHash64(toString(labels)),
    value          Float64 CODEC(Gorilla, ZSTD(1)),
    type           LowCardinality(String),
    retention_days UInt16 DEFAULT 90
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, name, series, timestamp)
TTL toDateTime(timestamp) + toIntervalDay(retention_days) DELETE
SETTINGS ttl_only_drop_parts = 0;
