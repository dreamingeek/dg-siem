-- Search terms match the raw line (Splunk-style), so index raw tokens too. Applies to new data;
-- existing parts get it as they merge.
ALTER TABLE {db}.events ADD INDEX IF NOT EXISTS idx_raw_tokens raw TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;
