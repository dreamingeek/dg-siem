-- ECS splits transport (tcp/udp) from application protocol (dns/http). Firewall logs need transport.
ALTER TABLE {db}.events ADD COLUMN IF NOT EXISTS network_transport LowCardinality(String) AFTER network_protocol;
