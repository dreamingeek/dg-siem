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

## Ready-made alerts

Alerts for a particular source come with its [integration pack](integrations.md): installing the pack adds them switched off, and they run only for the tenants the pack is on for. Open one from the pack's page to turn it on and choose who hears about it.

| Pack | Alerts |
|---|---|
| Windows | Repeated failed sign-ins from one source; account locked out; added to a privileged group; new user account; security or event log cleared; Remote Desktop sign-in from the internet; new service installed. Defender: malware detected; couldn't remove malware; protection turned off; signature updates failing |
| Phone systems | PBX: SIP brute force; SIP trunk not registering |
| authentik | Repeated failed logins; sign-in from an unusual country (edit the country list) |
| UniFi | Someone signed in to UniFi OS; one source hammering the firewall |
| Pangolin / Traefik | A site is returning errors |
| Proxmox VE | Stopped sending metrics; node CPU high; storage almost full |

If you added the Windows, Defender, PBX or authentik alerts from the old ready-made list, installing the pack takes them over (same name), keeping whether they're on and who they notify, and turns the pack on for the tenants already sending that data, so they keep running where they did.

**Alerts → Add ready-made alerts** still adds the ones that aren't about one source. Each runs for every tenant separately, emails the admin who added it, and opens an AlgaPSA ticket when it's High or Critical. They start switched on and are ordinary alerts afterwards: edit thresholds, **Test now**, or turn them off.

| Alert | Severity | Fires on |
|---|---|---|
| A log source went quiet | High | A host stopped sending a dataset for longer than usual ([health.md](health.md)) |
| An agent is offline or falling behind | High | No check-in for 30 minutes, a backed-up buffer, or a scrape target down ([health.md](health.md)) |
| No logs from a tenant | High | A tenant sent nothing for an hour (turn it off for tenants that aren't sending yet) |
| Traffic to a known-bad address / Sign-in from a known-bad address | High / Critical | Only when threat intel is on ([threat-intel.md](threat-intel.md)) |

Alerts already added are shown as such, so the list can be opened again.

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
