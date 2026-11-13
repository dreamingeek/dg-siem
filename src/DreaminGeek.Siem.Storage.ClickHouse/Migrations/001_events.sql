-- DG SIEM event store.
-- ECS field names are stored with dots replaced by underscores (source.ip -> source_ip).
-- Non-promoted ECS / vendor fields go in the `fields` map under their dotted ECS name.

CREATE TABLE IF NOT EXISTS {db}.events
(
    tenant_id         LowCardinality(String),
    timestamp         DateTime64(3, 'UTC'),
    ingest_time       DateTime64(3, 'UTC') DEFAULT now64(3),
    event_id          UUID DEFAULT generateUUIDv4(),

    host_name         LowCardinality(String),
    observer_ip       LowCardinality(String),

    event_dataset     LowCardinality(String),
    event_module      LowCardinality(String),
    event_action      LowCardinality(String),
    event_outcome     LowCardinality(String),
    log_level         LowCardinality(String),

    source_ip         String,
    source_port       UInt16,
    destination_ip    String,
    destination_port  UInt16,
    network_protocol  LowCardinality(String),

    user_name         String,

    message           String CODEC(ZSTD(3)),
    raw               String CODEC(ZSTD(3)),
    fields            Map(LowCardinality(String), String) CODEC(ZSTD(3)),

    -- Keyword search on message without scanning everything.
    INDEX idx_message_tokens message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_source_ip      source_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_destination_ip destination_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_user_name      user_name TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_field_keys     mapKeys(fields) TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, event_dataset, timestamp)
-- 120 days searchable. Phase 6 adds a cold volume (UNAS/S3) via a storage policy:
--   TTL toDateTime(timestamp) + INTERVAL 30 DAY TO VOLUME 'cold',
--       toDateTime(timestamp) + INTERVAL 120 DAY DELETE
TTL toDateTime(timestamp) + INTERVAL 120 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;
