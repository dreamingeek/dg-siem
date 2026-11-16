# Metrics

DG SIEM can collect metrics alongside your logs: an agent scrapes Prometheus `/metrics` pages the way a Prometheus server would, or receives metrics pushed in InfluxDB line protocol (Proxmox VE, Telegraf), and you chart and alert on them with the `mstats` search command. Metrics are kept per tenant, like events, for 90 days. They aren't part of the nightly event backups or the S3 cold tier yet.

## Scraping Prometheus exporters

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

## Receiving InfluxDB line protocol (Proxmox and others)

Some systems push metrics to an InfluxDB server instead of being scraped: Proxmox VE and Proxmox Backup Server (**Metric Server**), Telegraf's `influxdb`/`influxdb_v2` outputs, many network devices. An agent can stand in for that InfluxDB server. Add an **InfluxDb** input (HTTP) or an **InfluxDbUdp** input (UDP) to an agent the senders can reach (agent 0.7.0 or later):

```json
{ "type": "InfluxDb", "port": 8086, "job": "proxmox", "tokens": ["<a long random token>"] }
{ "type": "InfluxDbUdp", "port": 8089, "job": "proxmox" }
```

| Setting | Default | |
|---|---|---|
| `port` | (required) | 8086 and 8089 are InfluxDB's usual ports |
| `bindAddress` | `0.0.0.0` | |
| `job` | `influxdb` | The `job` label on every sample |
| `tokens` | | HTTP only. When set, a write must carry one: `Authorization: Token <t>` (v2), `?p=<t>` (v1), or `Bearer`/Basic as for the HEC input. Without tokens anyone who can reach the port can write. |
| `tls` | `false` | HTTP only: serve https with the agent's certificate |

Both `POST /api/v2/write` (InfluxDB 2) and `POST /write` (1.x) are accepted, gzip too; the `org`, `bucket` and `db` parameters are ignored. `/ping` and `/health` answer as InfluxDB does, so connection tests pass. UDP can't be authenticated: bind it to an internal address or firewall it.

Each line becomes one sample per numeric field, named `<measurement>_<field>` (the same names Telegraf's Prometheus output uses), with the line's tags as labels plus `job` and `instance` (the sender's address). String fields are skipped; `true`/`false` become 1/0. A tag called `job` or `instance` is kept as `exported_job` / `exported_instance`.

### Proxmox VE

In **Datacenter → Metric Server → Add → InfluxDB**:

- **Server**: the agent's address; **Port**: the input's port
- **Protocol**: HTTP (or UDP for an `InfluxDbUdp` input)
- **Organization**, **Bucket**: anything, e.g. `proxmox`
- **Token**: one of the input's tokens

Proxmox sends every 10 seconds. Nodes, guests and storages arrive with an `object` tag (`nodes`, `qemu`, `lxc`, `storages`) and `host` set to the node or guest name:

```
| mstats avg(cpustat_cpu) as cpu where object="nodes" by host span=5m       # node CPU (0-1)
| mstats latest(memory_memused) as used by host where object="nodes"
| mstats avg(system_cpu) where object="qemu" by host span=5m                # per-VM CPU
| mstats rate(nics_transmit) where object="nodes" by host, exported_instance span=5m   # bytes/s per NIC
| mstats latest(system_used) as used, latest(system_total) as total where object="storages" by host, nodename   # storage use
```

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
