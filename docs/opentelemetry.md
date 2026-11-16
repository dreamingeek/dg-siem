# OpenTelemetry

An agent can receive OpenTelemetry (OTLP) logs and metrics, the same way an OpenTelemetry Collector does. Two kinds of sender can then send straight to DG SIEM:

- **Apps instrumented with an OpenTelemetry SDK.** These send their own logs and metrics.
- **An OpenTelemetry Collector.** It can also tail files, read journald and Windows event logs, collect host metrics, and receive from many other sources.

The **OpenTelemetry** [integration pack](integrations.md) on the Integrations page sets this up for you: it generates a token, adds the input to an agent, and installs a dashboard for logs, one for host metrics, and an alert.

## The inputs

Add one or both inputs to an agent the senders can reach (agent 0.8.0 or later):

```json
{ "type": "OtlpGrpc", "port": 4317, "job": "otel", "tokens": ["<a long random token>"] }
{ "type": "Otlp", "port": 4318, "job": "otel", "tokens": ["<a long random token>"] }
```

| Input | Protocol | Used by |
|---|---|---|
| `OtlpGrpc` | OTLP over gRPC (HTTP/2). Accepts the `LogsService` and `MetricsService` `Export` calls, with gzip. | The Collector's `otlp` exporter, and most SDKs by default |
| `Otlp` | OTLP over HTTP. Accepts `POST /v1/logs` and `/v1/metrics`, as protobuf or JSON, with gzip. | The Collector's `otlphttp` exporter, browser and JavaScript SDKs, `curl` |

| Setting | Default | |
|---|---|---|
| `port` | (required) | 4317 for gRPC and 4318 for HTTP are the usual ports |
| `bindAddress` | `0.0.0.0` | |
| `job` | `otel` | Recorded on every event as `otel.job`. Used as a metric's `job` label when the sender sets no service name. |
| `tokens` | | When set, every request must include `Authorization: Bearer <token>`. Without tokens, anyone who can reach the port can send. |
| `tls` | `false` | Serve TLS with the agent's certificate. Senders then need `tls: { insecure: false }` and must trust it. |

**Traces are accepted and discarded.** This means a sender configured for all three signals doesn't log export errors. The inputs answer the way OTLP expects: HTTP 503, or gRPC status `UNAVAILABLE`, when the agent's buffer is full, so senders retry.

## Sending

**OpenTelemetry Collector:**

```yaml
exporters:
  otlp/dgsiem:
    endpoint: dg-log-col.example.net:4317
    tls: { insecure: true }
    headers: { authorization: "Bearer <token>" }
service:
  pipelines:
    logs:    { receivers: [filelog, journald], processors: [batch], exporters: [otlp/dgsiem] }
    metrics: { receivers: [hostmetrics],       processors: [batch], exporters: [otlp/dgsiem] }
```

Set `service.name` with the `resource` processor, so the logs get a dataset of their own and the metrics a `job`.

**An app's SDK**, through the standard environment variables:

```bash
OTEL_SERVICE_NAME=billing-api
OTEL_EXPORTER_OTLP_ENDPOINT=http://dg-log-col.example.net:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc        # or http/protobuf with port 4318
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer <token>
```

## What you get

**Logs** become events.

- **The record's body goes through the parsers like any other line.** A Traefik access log line tailed by a Collector still becomes `traefik.access`. A body nothing recognises gets the dataset `otel.<service name>` (for example `otel.billing-api`), unless the record has an `event.dataset` attribute.
- **`log.level`** comes from the severity text, or from the severity number when there's no text: trace, debug, info, warn, error, fatal.
- **`host.name`** comes from the resource's `host.name`, then `service.instance.id`, then the sender's address.
- **Fields** are added for `service.name`, `service.version` and the rest of the resource, `trace.id`, `span.id`, `otel.scope.name`, `otel.job`, and every record attribute under its own name. A body that's a map is kept as JSON.

```
otel.job=* log.level=error | stats count() by service.name
dataset=otel.billing-api trace.id=5b8efff798038103d269b633813fc60c
```

**Metrics** go into the metrics store, named as OpenTelemetry's Prometheus exporter names them, so `mstats` works on them like on scraped metrics.

- **Names:** dots become underscores, so `http.server.duration` becomes `http_server_duration`.
- **Histograms** become `_bucket` (with `le`), `_count` and `_sum`. Exponential histograms become `_count` and `_sum`. Summaries become the metric with a `quantile` label, plus `_count` and `_sum`.
- **Types:** cumulative monotonic sums are counters, so `rate()` works on them. Other sums are gauges. Delta sums (the amount per interval) are stored as they are: use `sum()` on those, not `rate()`.
- **Labels:** the data point's attributes, plus:
  - `job`: the service name, as `namespace/name` when a namespace is set;
  - `instance`: `service.instance.id`, else `host.name`, else the sender;
  - `host_name`: when the resource has a `host.name`.

  A point's own `job` or `instance` attribute is kept as `exported_job` or `exported_instance`.

```
| mstats rate(system_cpu_time) where state!="idle" by host_name span=5m
| mstats rate(http_server_duration_count) by job span=5m
```
