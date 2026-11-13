# Search language

DG SIEM uses a Splunk-style pipe language: a search, then commands separated by `|`.

```
dataset=unifi.firewall action=drop | stats count() as hits by src | sort -hits | head 10
```

Every search is limited to the tenants you can see and the selected time range. Results are capped at 10,000 rows (1,000 for raw events unless you `head` more).

The search boxes autocomplete as you type: commands after `|`, field names, values seen in your events over the last 24 hours, aggregations and functions, with a syntax reminder for the current command. Use the arrow keys and Tab (or Enter after arrowing) to pick, Esc to close and Ctrl+Space to bring the list back.

## The search clause

| Write | Matches |
|---|---|
| `ssh` | events whose raw line contains the word "ssh" (case-insensitive) |
| `"failed password"` | the exact phrase, anywhere in the raw line |
| `fail*` | wildcard text match |
| `field=value` | exact value. `host=AP-*` wildcards (case-insensitive) |
| `field=*`, `field!=*` | the field has a value / is empty (`src=*`: events with a source address) |
| `src=10.0.0.0/8` | an IP field inside a CIDR range |
| `dport>1024` | numeric comparison: `=` `!=` `<` `<=` `>` `>=` |
| `action IN (drop, reject)` | any of several values |
| `a b`, `a AND b`, `a OR b`, `NOT a`, `( … )` | boolean logic; spaces mean AND |

Fields use [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) names (`source.ip`, `event.action`, `rule.name`). Shortcuts:

| Shortcut | Field | | Shortcut | Field |
|---|---|---|---|---|
| `dataset`, `sourcetype` | `event.dataset` | | `src` | `source.ip` |
| `host` | `host.name` | | `dst`, `dest` | `destination.ip` |
| `action` | `event.action` | | `sport` / `dport` | `source.port` / `destination.port` |
| `user` | `user.name` | | `proto`, `transport` | `network.transport` |
| `level` | `log.level` | | `_time`, `timestamp` | `@timestamp` |
| `module` | `event.module` | | `_raw` | `raw` |
| `app`, `program` | `process.name` | | `status` | `http.response.status_code` |
| `method` | `http.request.method` | | `domain`, `vhost` | `url.domain` |
| `path` / `uri` | `url.path` / `url.original` | | `ua`, `useragent` | `user_agent.original` |
| `resource` | `pangolin.resource.name` | | | |

### Traefik / Pangolin access logs

Traefik's JSON access log (forwarded by rsyslog's imfile, or read as bare JSON) becomes `dataset=traefik.access`, with `http.*`, `url.*`, `user_agent.original`, `tls.*` and `event.duration` (nanoseconds). Requests that matched no router, such as scanners probing hostnames or paths you don't serve, get `action=unrouted`; served requests are `action=proxied`. 4xx responses are `level=warning` and 5xx `level=error`.

```
action=unrouted | top limit=20 path                       # what scanners are looking for
dataset=traefik.access status>=400 | stats count() by src, domain | sort -count
dataset=traefik.access | stats count(), p95(event.duration) by resource
```

### authentik

authentik's JSON logs (journald → rsyslog) are split into:

| Dataset | What |
|---|---|
| `authentik.event` | Audit events: `action=login`, `login_failed`, `logout`, `password_set`, `authorize_application`, `impersonation_started`, `suspicious_request`, exceptions. With `user.name` (for failed logins, the name that was tried), `source.ip`, GeoIP/ASN when authentik has them, and the request path and user agent. |
| `authentik.http` | Requests to the server and outposts (method, path, status, client, user). |
| `authentik.tasks` | Routine background-task chatter, separated so a drop rule can discard it (failed tasks stay in `authentik.server`). |
| `authentik.outpost`, `authentik.server` | Everything else. |

```
dataset=authentik.event action=login_failed | stats count() by user, src | sort -count
dataset=authentik.event action=login | stats count() by user, source.geo.country_iso_code
```

### CrowdSec

CrowdSec's logs (e.g. the container's output via Docker's syslog log driver with `tag: crowdsec`) are split into:

| Dataset | What |
|---|---|
| `crowdsec.decision` | A ban (or captcha) the local API recorded: `action=ban`, `src`, `rule.name` (the scenario, e.g. `crowdsecurity/http-probing`), `crowdsec.decision.duration`, country and ASN. |
| `crowdsec.alert` | A scenario that triggered (`action=scenario_triggered`), with the event count. |
| `crowdsec.appsec` | WAF notices, e.g. `action=allowlisted`. |
| `crowdsec.lapi` | The local API's access log, mostly bouncers polling every few seconds. Drop it with a drop rule. |
| `crowdsec.log` | Everything else. |

```
dataset=crowdsec.decision | top limit=20 rule.name
dataset=crowdsec.decision | stats count() by source.geo.country_iso_code | sort -count
```

Correlate with the other sources by address, e.g. what a banned IP did first:

```
src=45.148.10.12 | table @timestamp, dataset, action, status, path, user
```

### Asterisk / FreePBX

Asterisk's `full` and `security` logs (tailed by the agent; see [Phones](phones.md)) are split into:

| Dataset | What |
|---|---|
| `asterisk.security` | Failed SIP requests (`action=auth-failed`, `unknown-account`, `acl-denied`) and the security log's events (`challenge-response-failed`, `invalid-password`, `successful-auth`, ...), with `user` (the extension tried), `src` and country. |
| `asterisk.registration` | Phones registering and dropping off: `registered`, `unregistered`, `endpoint-reachable` / `endpoint-unreachable`, `contact-reachable` with `asterisk.rtt_ms`. `src` is the address the phone registered from; `asterisk.contact_private_ip` is its own LAN address behind NAT. |
| `asterisk.sip` | SIP packets, when `pjsip set logger on` is enabled: `sip.method`, `sip.status_code`, `sip.call_id`, `sip.from.user`, `sip.to.user` and the phone model in `ua`. |
| `asterisk.call` | Dialplan steps (`action=dialplan`, `asterisk.context`, `asterisk.application`) and dial progress (`dial`, `ringing`, `answered`). `asterisk.call_id` (`C-0000001a`) ties one call's lines together. |
| `asterisk.log` | Everything else, with the Asterisk source file in `log.origin.file.name`. |

```
dataset=asterisk.security outcome=failure | stats count() as tries, dc(user) as extensions by src, source.geo.country_iso_code | sort -tries
dataset=asterisk.registration action=endpoint-unreachable | stats count() by user, host
dataset=asterisk.sip | stats latest(ua) by user, src
```

### FreeSWITCH / FusionPBX

`freeswitch.log` becomes `freeswitch.security` (`auth-failed`, `unknown-account`, `acl-denied`), `freeswitch.registration` (phones and trunk gateways), `freeswitch.call` (`new-channel`, `answered`, `hangup` with `freeswitch.hangup_cause`) and `freeswitch.log`. See [Phones](phones.md#freeswitch--fusionpbx--fs-pbx).

## Commands

| Command | Example |
|---|---|
| `where` | `where dport > 1024 AND NOT user IN ("root", "admin")` |
| `eval` | `eval kb = network.bytes / 1024, label = host . "-" . action` |
| `rex` | `rex field=message "user=(?<user>\w+) from (?<ip>\S+)"` |
| `stats` | `stats count() as hits, dc(src), avg(network.bytes), p95(network.bytes) by host, dataset` |
| `top` | `top limit=5 src by host` (count and percent) |
| `fieldsummary` | `fieldsummary maxvals=5 host, src, dport` (top values of several fields; no fields = the sidebar's set) |
| `timechart` | `timechart span=15m count by dataset` (span is automatic if omitted) |
| `sort` | `sort -hits, +host` |
| `head` | `head 20` |
| `dedup` | `dedup host` |
| `table` / `fields` | `table @timestamp, src, dst, action`, `fields - message` |

**Aggregations:** `count`, `count(field)`, `dc`, `sum`, `avg`, `min`, `max`, `median`, `p50`/`p90`/`p95`/`p99`, `values`, `earliest`, `latest`.

**Functions** (in `where`/`eval`): `lower`, `upper`, `len`, `tostring`, `tonumber`, `round`, `abs`, `substr`, `replace` (regex), `if`, `coalesce`, `isnull`, `isnotnull`, `like`, `match` (regex), `cidrmatch`, `now`, `ago("2h")`. Operators: `+ - * / %`, `.` joins strings.

## Examples

```
dataset=unifi.firewall action=drop | top limit=20 src
dataset=unifi.os | table @timestamp, host, user, src, message
dataset=unifi.vpn NOT action=ipsec_keepalive | stats count by host, message | sort -count
* | timechart span=1h count by dataset
dataset=unifi.firewall | stats dc(dst) as targets, count by src | where targets > 20
```

## The search page

- **Field sidebar.** For raw-event searches, the top values of common fields across the whole result (not just the rows shown). Click a value to add `field="value"` to the search; click **−** to exclude it.
- **Event details.** Click an event to see every field (including vendor fields like `rule.name`), the raw line, and **surrounding events**: the 15 events before and after it from the same host. Each field has **+**/**−** to filter on it.
- **Charts.** `timechart` results are graphed above the table (drag the slider to zoom).
- **Saved searches.** Save the current search and time range under a name. You see your own; global admins see everyone's.
- **Shareable URLs.** The search, time range and tenant are in the URL, so you can bookmark them and the back button works.
