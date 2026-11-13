# Alerting

An alert is a search that runs on a schedule. When it matches, DG SIEM emails the people you list and/or opens a ticket in AlgaPSA under the tenant's client. Alerts are managed by global admins under **Alerts**; where they're delivered is set under **Administration → Notifications**.

## Set up delivery first

**Administration → Notifications**

- **General**: the address people use to reach DG SIEM (for the links in emails and tickets), and the time zone that schedules like "daily at 8:00" and alert times use.
- **Email**: your SMTP relay. Username and password are optional for relays that allow this server by IP. Use **Send test** to check it.
- **AlgaPSA tickets**: the AlgaPSA address and an API key (AlgaPSA: your profile → API keys; the key's user needs to read boards, clients and priorities and to create tickets). **Save and connect** loads your boards, clients and priorities. Then choose:
  - the default board for alert tickets;
  - which AlgaPSA priority each alert severity (Low, Medium, High, Critical) gets;
  - each tenant's client, plus a board when one client's tickets belong somewhere other than the default. Tenants left on "No tickets" can still email.

Passwords and API keys are stored encrypted with the same key ring as login cookies (`/var/lib/dg-siem/keys`). If that folder is lost, enter them again.

## Security alerts

**Alerts → Add ready-made alerts** adds detections for the sources DG SIEM parses, the two health alerts (a log source went quiet, an agent offline or falling behind: see [health.md](health.md)), and, when threat intel is on, two for known-bad addresses ([threat-intel.md](threat-intel.md)). Each runs for every tenant separately, emails the admin who added it, and opens an AlgaPSA ticket when it's High or Critical. They start switched on and are ordinary alerts afterwards: edit thresholds, **Test now**, or turn them off.

| Alert | Severity | Fires on |
|---|---|---|
| Windows: repeated failed sign-ins from one source | High | 20+ failures, or 5+ accounts tried, from one address in 15 minutes (guessing, spraying) |
| Windows: account locked out | Medium | Lockouts (4740), with the computer the attempts came from |
| Windows: added to a privileged group | High | Members added to Administrators, Domain/Enterprise/Schema Admins, Account/Backup Operators, Remote Desktop Users, DnsAdmins |
| Windows: new user account | Medium | Accounts created (4720) |
| Windows: security or event log cleared | Critical | 1102 / 104 |
| Windows: remote desktop sign-in from the internet | High | RDP sign-ins from public addresses (add `NOT src=` for a known VPN address) |
| Windows: new service installed | Medium | 7045 / 4697 (quiet for a day per service) |
| Defender: malware detected | High | Detections and suspicious behaviour |
| Defender: couldn't remove malware | Critical | The remediation failed |
| Defender: protection turned off | Critical | Real-time/virus/spyware protection off, tamper protection blocked a change |
| Defender: signature updates failing | Medium | Checked every 4 hours |
| PBX: SIP brute force | Medium | 50+ failed SIP requests from one address in 15 minutes (FreePBX, FusionPBX) |
| PBX: SIP trunk not registering | High | 3+ trunk ping/registration failures in 15 minutes |
| authentik: repeated failed logins | High | 10+ failures, or 5+ accounts, from one address in 15 minutes |
| No logs from a tenant | High | A tenant sent nothing for an hour (turn it off for tenants that aren't sending yet) |

Alerts already added are shown as such, so the list can be opened again when new detections are added.

## Create an alert

Run a search, then choose **Create alert**. The editor opens with the search, tenant and time range filled in.

| Setting | What it does |
|---|---|
| **Search** | Any search. Event searches alert on how many events match; searches ending in `stats`, `top` or `table` alert on how many rows they return. |
| **Tenant** | One tenant, or *each tenant separately*: the search runs once per tenant, so every alert and ticket belongs to exactly one client. |
| **Looks back over** | The window each run checks. Make it at least as long as the time between runs, or events in between are never checked (the editor warns you). |
| **Alert when the search finds** | Anything, more than N, or fewer than N. *Fewer than* catches silence, e.g. fewer than 1 event from a firewall in an hour. |
| **Send** | *One alert per run*, or *one alert per result row*. Per-row suits `stats count() by src`: each source gets its own alert and ticket (at most 50 per run). Rows with an empty key are skipped. |
| **Severity** | Shown in the email and mapped to the AlgaPSA priority. |
| **Runs** | Every minute up to weekly, or any 5-field cron expression in the configured time zone. |
| **Stay quiet for** | After an alert fires, the same alert (same tenant and, per row, the same key) is suppressed this long. Suppressed repeats are counted in the history. |
| **A repeat means the same** | For per-row alerts: the fields that identify "the same" alert. By default, the text columns of the result (so `stats count() by src` keys on `src`, not the changing count). |
| **Email to / ticket** | Comma-separated recipients; tick the box to open AlgaPSA tickets. |

**Test now** runs the alert against current data for every tenant it covers and shows what it would send, without sending anything.

### Examples

```
# A source hammering the firewall (one alert per source, per tenant)
dataset=unifi.firewall action=blocked | stats count() by src | where count > 100

# Someone signed in to UniFi OS (one alert per run, with the events attached)
dataset=unifi.os action=admin_accessed_unifi_os

# A gateway stopped sending logs: "fewer than 1", look back 1 hour, run hourly
host=ACME-GW
```

## Tickets and repeats

A ticket is titled `[DG SIEM] <alert name> - <key> (<tenant>)`. Its description holds the facts, the first 10 results and a link to the search. It also carries an AlgaPSA external link (system `dg-siem`) back to the alert.

If the same alert fires again after its quiet period while its ticket is still open, DG SIEM adds an internal note to that ticket instead of opening another. Once the ticket is closed, the next repeat opens a new one.

## History

**Alerts → History** lists every alert sent, with what each action did: email sent, ticket opened or noted, or the error. Click a row for the matching results. History is kept for 180 days.

The alert list shows each alert's last run, last error, next run and how often it fired in the last 7 days. **Run now** runs an alert immediately (repeats are still suppressed).
