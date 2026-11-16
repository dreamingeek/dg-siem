# Search language

DG SIEM uses a Splunk-style pipe language: a search, then commands separated by `|`.

```
dataset=unifi.firewall action=blocked | stats count() as hits by src | sort -hits | head 10
```

Searches run on events. Metrics (from Prometheus scrapes, InfluxDB pushes and OpenTelemetry) are searched with `mstats` instead; see [Metrics: mstats](#metrics-mstats).

Every search is limited to the tenants you can see and the selected time range. Results are capped at 10,000 rows, or 1,000 for raw events unless you `head` more.

The search boxes autocomplete as you type: commands after `|`, field names, values seen in your events over the last 24 hours, and aggregations and functions, with a syntax reminder for the current command. To pick an entry, use the arrow keys and then Tab, or Enter once you've arrowed to it. Esc closes the list, and Ctrl+Space brings it back.

## The search clause

| Write | Matches |
|---|---|
| `ssh` | Events whose raw line contains the word "ssh" (case-insensitive). |
| `"failed password"` | The exact phrase, anywhere in the raw line. |
| `fail*` | A wildcard text match anywhere in the raw line. |
| `field=value` | That exact value (case-sensitive). Quote values that contain spaces or symbols: `user="Front Desk"`. |
| `host=AP-*` | A wildcard match on a field (case-insensitive). |
| `field=*`, `field!=*` | The field has a value, or is empty. `src=*` finds events with a source address. |
| `src=10.0.0.0/8` | An IP field inside a CIDR range. `NOT src=192.168.0.0/16` excludes one. |
| `dport>1024` | A numeric comparison: `=` `!=` `<` `<=` `>` `>=`. |
| `@timestamp>="2026-11-15 08:00"` | A time comparison (UTC). |
| `action IN (drop, reject)` | Any of several exact values. Wildcards don't work inside `IN`, so write `(dataset=asterisk.* OR dataset=freeswitch.*)` instead. |
| `a b`, `a AND b`, `a OR b`, `NOT a`, `( … )` | Boolean logic. A space means AND. |

Fields use [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) names, such as `source.ip`, `event.action` and `rule.name`. A vendor's own fields keep their names (`crowdsec.decision.duration`, `freeswitch.hangup_cause`); open an event to see them all.

### Field shortcuts

| Shortcut | Field | | Shortcut | Field |
|---|---|---|---|---|
| `dataset`, `sourcetype` | `event.dataset` | | `src`, `src_ip` | `source.ip` |
| `module` | `event.module` | | `sport`, `src_port` | `source.port` |
| `action` | `event.action` | | `dst`, `dest`, `dst_ip` | `destination.ip` |
| `outcome` | `event.outcome` | | `dport`, `dst_port`, `dest_port` | `destination.port` |
| `host` | `host.name` | | `proto`, `transport` | `network.transport` |
| `observer` | `observer.ip` (the sender) | | `country`, `city` | `source.geo.country_iso_code`, `source.geo.city_name` |
| `level`, `severity` | `log.level` | | `asn` | `source.as.number` |
| `user` | `user.name` | | `org`, `as_org` | `source.as.organization.name` |
| `msg` | `message` | | `dst_country`, `dst_org` | the same for `destination.*` |
| `app`, `program` | `process.name` | | `status` | `http.response.status_code` |
| `_time`, `time`, `timestamp` | `@timestamp` | | `method` | `http.request.method` |
| `_raw` | `raw` | | `domain`, `vhost` | `url.domain` |
| `tenant`, `tenant_id` | the tenant | | `path` / `uri` | `url.path` / `url.original` |
| `_id` | `event.id` | | `ua`, `useragent` | `user_agent.original` |
| `resource` | `pangolin.resource.name` | | `threat_feed`, `threat_ip`, `threat_on`, `threat_reason` | `threat.*` ([threat-intel.md](threat-intel.md)) |

Country and network come from GeoIP ([geoip.md](geoip.md)) for any public `source.ip` or `destination.ip`.

## Commands

| Command | Example |
|---|---|
| `where` (or `search`) | `where dport > 1024 AND NOT user IN ("root", "admin")` |
| `eval` | `eval kb = network.bytes / 1024, label = host . "-" . action` |
| `rex` | `rex field=message "user=(?<user>\w+) from (?<ip>\S+)"` |
| `stats` | `stats count() as hits, dc(src), avg(network.bytes), p95(network.bytes) by host, dataset` |
| `top` | `top limit=5 src by host` (count and percent; 10 by default) |
| `fieldsummary` | `fieldsummary maxvals=5 host, src, dport` (top values of several fields; no fields means the sidebar's set) |
| `timechart` | `timechart span=15m count by dataset` (the span is automatic if omitted) |
| `sort` | `sort -hits, +host` or `sort hits desc` |
| `head` | `head 20` (10 if no number is given) |
| `dedup` | `dedup host, user` |
| `table` / `fields` | `table @timestamp, src, dst, action`; `fields - message` removes fields |
| `mstats` | `| mstats avg(node_load1) by instance span=5m` (metrics, [below](#metrics-mstats)) |

**Aggregations** (in `stats` and `timechart`):

| Aggregation | |
|---|---|
| `count`, `count(field)` | Events, or events where the field has a value. |
| `dc(field)` (`distinct_count`) | Distinct values. |
| `sum`, `avg` (`mean`), `min`, `max`, `median` | Of a numeric field. |
| `p50`, `p90`, `p95`, `p99`, or any `p1` to `p99` | Percentiles. |
| `values(field)` | Up to 100 distinct values, sorted. |
| `earliest(field)` (`first`), `latest(field)` (`last`) | The value from the oldest or newest event. |

**Functions** (in `where` and `eval`):

| Function | |
|---|---|
| `lower(x)`, `upper(x)`, `len(x)` (`length`) | Text case and length. |
| `substr(x, start, length)`, `replace(x, regex, with)` | Parts of text. `replace` takes a regex. |
| `tostring(x)`, `tonumber(x)`, `round(x, digits)`, `abs(x)` | Conversions and rounding. |
| `if(condition, then, else)`, `coalesce(a, b, …)` | Choosing a value. |
| `isnull(x)`, `isnotnull(x)` | Whether a field is empty. |
| `like(x, "a%")`, `match(x, regex)`, `cidrmatch("10.0.0.0/8", ip)` | Pattern and network tests. |
| `now()`, `ago("2h")` (`relative_time`) | Times, e.g. `where @timestamp > ago("15m")`. |

Operators: `+ - * / %`, and `.` joins strings. Comparisons: `= == != < <= > >=`, plus `AND`, `OR`, `NOT` and `IN (…)`.

## Metrics: mstats

`mstats` searches the metrics store instead of events. Metrics come from:

- Prometheus scrapes ([metrics.md](metrics.md));
- InfluxDB line protocol, such as Proxmox's Metric Server ([metrics.md](metrics.md#receiving-influxdb-line-protocol-proxmox-and-others));
- OpenTelemetry ([opentelemetry.md](opentelemetry.md)).

Start the search with it (the leading `|` is optional):

```
| mstats <aggregation>(<metric>) [as name], … [where label=value …] [by label, …] [span=5m]
```

| Part | |
|---|---|
| Aggregations | `avg` (`mean`), `min`, `max`, `sum` and `count` of the samples. `latest` (`last`) is the newest value. `rate` is the per-second increase of a counter and `increase` its total increase; both cope with counter resets. With `span=`, `rate` is per second within each bucket; without it, over the whole time range. |
| `where` | Label filters, separated by spaces: `job="netprox"`, `instance!="test:9100"`, `host="pve*"` (`*` is a wildcard; label matches are case-sensitive). Quote values that contain `:`, `/` or `*`. |
| `by` | Labels to group by. In a chart, several labels join into one series name, `a / b`. |
| `span=` | Bucket size, which makes the result a chart over time. Without it, you get a table with one row per group. |

Aggregations work per series first, then across the series in a group. So `avg(cpu) by host` averages each CPU series over the bucket, then averages those across the host's series. `rate(x) by job` adds the rates of the job's series together.

After `mstats` you can continue with `where`, `eval`, `sort`, `head`, `table`, `fields` and `stats`:

```
| mstats rate(http_requests_total) by instance span=5m
| mstats avg(node_load1) as load by instance | where load > 4 | sort -load
| mstats latest(up) as up by job, instance | where up = 0                      # targets that are down
| mstats latest(system_used) as used, latest(system_total) as total where object="storages" by host, nodename | eval pct = round(used / total * 100, 1) | sort -pct
| mstats count(cpustat_cpu) as samples | where samples > 0                     # is anything arriving?
```

How metrics are named depends on where they come from:

| Source | Names | Labels |
|---|---|---|
| Prometheus scrape | As the exporter writes them, e.g. `node_load1`, `http_requests_total`. | The exporter's labels, plus `job` (the input's job) and `instance` (the target). The scrape adds `up`, `scrape_duration_seconds` and `scrape_samples_scraped`. |
| InfluxDB line protocol | `<measurement>_<field>`, e.g. `cpustat_cpu` and `memory_memused` from Proxmox. | The line's tags, plus `job` and `instance` (the sender). |
| OpenTelemetry | Dots become underscores, e.g. `system.cpu.time` becomes `system_cpu_time`. Histograms are `_bucket`, `_count` and `_sum`. | The point's attributes, plus `job` (the service), `instance` and `host_name`. |

A tag or attribute that's itself called `job` or `instance` is kept as `exported_job` or `exported_instance`. There's no list of metric names in the UI yet. Look at the exporter's `/metrics` page, the source's documentation, or its integration pack's dashboards.

## Sources

The [integration packs](integrations.md) add dashboards and alerts for each of these.

### UniFi

UniFi gateways and consoles send syslog: the SIEM Server integration in CEF, plus older kernel-style lines.

| Dataset | What |
|---|---|
| `unifi.firewall` | Firewall policy matches: `action=blocked` or `allowed` (the gateway's own word, such as `block` or `drop`, is in `unifi.firewall.action`), `src`, `dst`, `dport`, `proto` and `rule.name`. |
| `unifi.os` | Console events, e.g. `action=admin_accessed_unifi_os` with `user` and `src`. |
| `unifi.vpn`, `unifi.dhcp` | VPN tunnels and clients; DHCP leases with `client.mac`, `client.ip` and `unifi.dhcp.hostname`. |
| `unifi.ap`, `unifi.switch`, `unifi.device` | Access points (clients joining: `action=sta_join`), switches and other devices. |
| `unifi.security`, `unifi.monitoring`, `unifi.system`, … | Other CEF categories, by their UniFi category, and system lines (`unifi.dpi` for DPI statistics). |

```
dataset=unifi.firewall event.type=denied | top limit=20 src
dataset=unifi.firewall action=blocked | stats count() as blocks, dc(dport) as ports by src, country, org | sort -blocks
dataset=unifi.os | table @timestamp, host, user, src, message
dataset=unifi.vpn NOT action=ipsec_keepalive | stats count() by host, message | sort -count
```

### Traefik / Pangolin access logs

Traefik's JSON access log (read by an agent, forwarded by rsyslog's imfile, or sent as bare JSON) becomes `dataset=traefik.access`, with:

- `http.*`, `url.*`, `user_agent.original` and `tls.*`;
- `event.duration` in nanoseconds;
- `pangolin.resource.name` (`resource`) for Pangolin sites.

Requests that matched no router get `action=unrouted`: scanners probing hostnames or paths you don't serve. Served requests are `action=proxied`. 4xx responses are `level=warning` and 5xx responses `level=error`.

```
action=unrouted | top limit=20 path                       # what scanners are looking for
dataset=traefik.access status>=400 | stats count() by src, domain | sort -count
dataset=traefik.access | stats count(), p95(event.duration) by resource
```

### authentik

authentik's JSON logs are split into:

| Dataset | What |
|---|---|
| `authentik.event` | Audit events: `action=login`, `login_failed`, `logout`, `password_set`, `authorize_application`, `impersonation_started`, `suspicious_request` and exceptions. Includes `user.name` (for failed logins, the name that was tried), `source.ip`, GeoIP and ASN when authentik has them, and the request path and user agent. |
| `authentik.http` | Requests to the server and outposts: method, path, status, client and user. |
| `authentik.tasks` | Routine background-task chatter, kept separate so a drop rule can discard it. Failed tasks stay in `authentik.server`. |
| `authentik.outpost`, `authentik.server` | Everything else. |

```
dataset=authentik.event action=login_failed | stats count() by user, src | sort -count
dataset=authentik.event action=login | stats count() by user, country
```

### CrowdSec

CrowdSec's logs (for example the container's output, via Docker's syslog log driver with `tag: crowdsec`) are split into:

| Dataset | What |
|---|---|
| `crowdsec.decision` | A ban (or captcha) the local API recorded: `action=ban`, `src`, `rule.name` (the scenario, e.g. `crowdsecurity/http-probing`), `crowdsec.decision.duration`, country and ASN. |
| `crowdsec.alert` | A scenario that triggered (`action=scenario_triggered`), with the event count. |
| `crowdsec.appsec` | WAF notices, e.g. `action=allowlisted`. |
| `crowdsec.lapi` | The local API's access log, mostly bouncers polling every few seconds. Drop it with a drop rule. |
| `crowdsec.log` | Everything else. |

```
dataset=crowdsec.decision | top limit=20 rule.name
dataset=crowdsec.decision | stats count() by country | sort -count
```

To see what a banned address did before it was banned, correlate across sources by address:

```
src=45.148.10.12 | table @timestamp, dataset, action, status, path, user
```

### Windows

The Windows agent reads the event logs into `windows.security`, `windows.system`, `windows.application`, `windows.defender`, `windows.powershell` and `windows.sysmon`.

- `event.code` is the event ID.
- `event.action` is a readable name, such as `logged-in`, `logon-failed`, `locked-out-user-account`, `added-member-to-group`, `service-installed`, `audit-log-cleared` or `malware-detected`.
- Event data is under `winlog.*`, e.g. `winlog.logon.type`.

See [windows.md](windows.md).

```
dataset=windows.security action=logon-failed | stats count() as failures, dc(user) as accounts by src, host | sort -failures
dataset=windows.security action=logged-in winlog.logon.type=RemoteInteractive | table @timestamp, host, user, src
```

### Asterisk / FreePBX

Asterisk's `full` and `security` logs (tailed by the agent; see [Phones](phones.md)) are split into:

| Dataset | What |
|---|---|
| `asterisk.security` | Failed SIP requests (`action=auth-failed`, `unknown-account`, `acl-denied`) and the security log's events (`challenge-response-failed`, `invalid-password`, `successful-auth`, ...), with `user` (the extension tried), `src` and country. |
| `asterisk.registration` | Phones registering and dropping off: `registered`, `unregistered`, `endpoint-reachable` / `endpoint-unreachable`, and `contact-reachable` with `asterisk.rtt_ms`. `src` is the address the phone registered from; `asterisk.contact_private_ip` is its own LAN address behind NAT. |
| `asterisk.sip` | SIP packets, when `pjsip set logger on` is enabled: `sip.method`, `sip.status_code`, `sip.call_id`, `sip.from.user`, `sip.to.user`, and the phone model in `ua`. |
| `asterisk.call` | Dialplan steps (`action=dialplan`, `asterisk.context`, `asterisk.application`) and dial progress (`dial`, `ringing`, `answered`). `asterisk.call_id` (e.g. `C-0000001a`) ties one call's lines together. |
| `asterisk.log` | Everything else, with the Asterisk source file in `log.origin.file.name`. |

```
dataset=asterisk.security outcome=failure | stats count() as tries, dc(user) as extensions by src, country | sort -tries
dataset=asterisk.registration action=endpoint-unreachable | stats count() by user, host
dataset=asterisk.sip | stats latest(ua) by user, src
```

### FreeSWITCH / FusionPBX / FS PBX

`freeswitch.log` is split into:

- `freeswitch.security`: `auth-failed`, `unknown-account`, `acl-denied`.
- `freeswitch.registration`: phones (`registered`, `expired`, with `freeswitch.contact_private_ip`) and trunk gateways (`gateway-ping-ok`, `gateway-ping-failed`).
- `freeswitch.call`: `new-channel`, `answered`, and `hangup` with `freeswitch.hangup_cause`.
- `freeswitch.log`: everything else.

See [Phones](phones.md#freeswitch--fusionpbx--fs-pbx).

```
dataset=freeswitch.call action=hangup | top limit=10 freeswitch.hangup_cause
dataset=freeswitch.registration action=registered | stats latest(src), latest(freeswitch.contact_private_ip) by user
```

### HTTP Event Collector and Docker

Events sent to an agent's HEC input are parsed like any line. Anything not recognised gets the dataset from the input, the sourcetype (`docker:web` becomes `docker.web`), or `hec`. The HEC metadata is kept as `hec.source`, `hec.sourcetype` and `hec.index`. See [agents.md](agents.md).

### OpenTelemetry

OTLP log records go through the parsers like any line. One nothing recognises gets the dataset `otel.<service name>`, with:

- `log.level` from the record's severity;
- `service.name`, `trace.id`, `span.id` and `otel.scope.name`;
- every attribute under its own name.

`otel.job=*` matches everything that arrived over OpenTelemetry. See [opentelemetry.md](opentelemetry.md).

```
otel.job=* log.level IN (error, fatal) | stats count() by service.name
dataset=otel.billing-api trace.id=5b8efff798038103d269b633813fc60c
```

## More examples

```
* | timechart span=1h count by dataset                                  # what's arriving, by source
dataset=unifi.firewall | stats dc(dst) as targets, count() by src | where targets > 20   # one source scanning many hosts
country=* NOT country IN (US, CA) action IN (login, logged-in) | table @timestamp, dataset, user, src, country
src=* | stats dc(dataset) as sources, values(dataset) by src | where sources >= 3 | sort -sources   # an address seen by several systems
level IN (error, fatal) | stats count() by dataset, host | sort -count
```

## The search page

- **Time range and tenant.** Use a preset range or a custom one. Global admins and people with several tenants can narrow the search to one tenant.
- **Activity strip.** Above raw events, a bar per time bucket shows how many events matched. Click a bar to zoom into that bucket.
- **One line per event.** Results show one line each; **Show full messages** expands them.
- **Field sidebar.** For raw-event searches, the top values of common fields across the whole result, not just the rows shown. Click a value to add `field="value"` to the search, or **−** to exclude it.
- **Event details.** Click an event to see every field (including vendor fields like `rule.name`), the raw line, and **surrounding events**: the 15 events before and after it from the same host. Each field has **+** and **−** to filter on it.
- **Charts.** `timechart` and `mstats … span=` results are graphed above the table, as bars for events and lines for metrics. Drag the slider to zoom.
- **Saved searches.** Save the current search and time range under a name. You see your own; global admins see everyone's.
- **Shareable URLs.** The search, time range and tenant are in the URL, so you can bookmark them and the back button works.
