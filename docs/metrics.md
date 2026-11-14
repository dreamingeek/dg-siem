# Metrics

DG SIEM can collect Prometheus metrics alongside your logs: an agent scrapes `/metrics` pages the way a Prometheus server would, and you chart and alert on them with the `mstats` search command. Metrics are kept per tenant, like events, for 90 days. They aren't part of the nightly event backups or the S3 cold tier yet.

## Collecting

Add a **Prometheus** input to an agent (**Agents → Edit inputs**) at the site whose exporters you want to scrape. It takes the same pieces as a Prometheus `scrape_configs` job:

```json
{
  "type": "Prometheus",
  "job": "netprox",
  "targets": ["netprox.example.net:81"],
  "authorization": { "credentials": "<the token>" },
  "scrapeInterval": "1m"
}
```

That is the same as this Prometheus job:

```yaml
scrape_configs:
  - job_name: netprox
    authorization: { credentials: <the token> }
    static_configs: [{ targets: ["netprox.example.net:81"] }]
```

| Setting | Default | |
|---|---|---|
| `job` | (required) | The `job` label on every sample |
| `targets` | (required) | `host:port` of each exporter; each becomes the `instance` label |
| `metricsPath` | `/metrics` | |
| `scheme` | `http` | or `https` |
| `scrapeInterval` | `1m` | `15s`, `30s`, `1m`, … (5s to 1h) |
| `scrapeTimeout` | `10s` | at most the interval |
| `authorization` | | `{ "credentials": "..." }` sends `Authorization: Bearer ...`; add `"type"` for another scheme |
| `basicAuth` | | `{ "username": "...", "password": "..." }` |
| `insecureSkipVerify` | `false` | https: accept self-signed certificates |

Each scrape goes through the agent's disk buffer like logs, so nothing is lost while the server is unreachable. A page bigger than 8 MB counts as a failed scrape.

As in Prometheus, every scrape also records:

- `up`: 1 if the scrape worked, 0 if it didn't (the agent's log says why);
- `scrape_duration_seconds` and `scrape_samples_scraped`.

A target's own `job` or `instance` label is kept as `exported_job` / `exported_instance`.

## Charting: `mstats`

`mstats` starts a search (the leading `|` is optional) and aggregates metric samples instead of events:

```
| mstats <aggregation>(<metric>) [as name], ... [where label=value ...] [by label, ...] [span=5m]
```

| Aggregation | |
|---|---|
| `avg`, `min`, `max` | of the samples |
| `sum` | of each series' average: e.g. total memory across instances |
| `latest` | the most recent value |
| `count` | number of samples |
| `rate` | per-second increase of a counter (handles counter resets) |
| `increase` | total increase of a counter over the bucket |

- `where` filters on labels: `job="netprox"`, `instance!="test*"` (`*` is a wildcard). Quote values that contain `:`, `*` or spaces.
- `by` splits by labels. With `span=` the result is a time chart; with several `by` labels, the chart's series are named `a / b`.
- Without `span=`, you get one row per group over the whole time range: a table you can `sort`, `where` and `head`.

```
| mstats latest(up) as up by job, instance | where up = 0          # targets that are down
| mstats rate(http_requests_total) as rps by instance span=5m       # requests per second
| mstats avg(node_load1) by instance span=5m
| mstats max(process_resident_memory_bytes) as mem by instance | sort -mem | head 10
| mstats rate(http_requests_total) where code="5*" by instance span=1m
```

Metric names with characters other than letters, digits and `_` (such as `:` in recording rules) go in quotes: `avg("job:requests:rate5m")`.

## Dashboards and alerts

- **Dashboards:** a time-chart panel (line, area or bars) takes any `mstats ... span=` search; a stat or table panel takes one without `span=`.
- **Alerts:** a search alert on `| mstats latest(up) as up by job, instance | where up = 0` fires when a target stops answering. Any threshold works the same way: `| mstats avg(node_load1) as load by instance | where load > 4`.
