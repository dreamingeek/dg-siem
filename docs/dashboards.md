# Dashboards

Dashboards are panels built from searches, on a drag-and-resize grid. They're under **Dashboards** in the side rail (global admins).

## Ready-made dashboards

Dashboards for one source come with its [integration pack](integrations.md): installing the pack adds them.

| Pack | Dashboard |
|---|---|
| Pangolin / Traefik | **Pangolin traffic**: requests, 4xx/5xx and p95 response time; traffic by resource; errors by status; top clients; slowest resources |
| UniFi | **UniFi firewall**: blocks per tenant, top rules, blocked sources and destination ports |
| CrowdSec | **CrowdSec**: bans, scenarios, countries and networks, most banned addresses |
| authentik | **authentik sign-ins**: sign-ins and failures over time, by country, by user and source |
| Windows | **Windows security**: failed sign-ins, lockouts, Remote Desktop sign-ins, Defender detections |
| Phone systems | **Phone systems**: failed SIP attempts, who's trying, trunk failures, failed calls |
| Proxmox VE | **Proxmox overview**: nodes, guests, CPU, memory, network, storage |

**Security overview** spans several sources (CrowdSec bans, authentik failed logins, scanner requests and UniFi firewall blocks; bans by scenario and country; what scanners probe for), so it stays a starter: **Add the Security overview dashboard** on the Dashboards page creates it, and the button comes back if you delete it.

## Viewing

- **Tenants**: all tenants, or one. Every panel is scoped to the tenants you choose.
- **Time range**: last 15 minutes to last 30 days.
- **Auto-refresh**: off, or every 1, 5 or 15 minutes.
- **Single numbers** show the change from the previous period of the same length ("+20% vs previous") and, when the search ends in a plain `| stats`, a sparkline of the same value over time.
- The magnifier on a panel opens its search on the Search page.

## Editing

Choose **Edit**. Drag panels by their title and resize them from the bottom-right corner. **Add panel** opens the panel editor; **Edit** and **×** on a panel change or remove it. **Save** keeps the layout and makes the current time range and refresh the dashboard's defaults; **Cancel** throws away the changes.

From the Search page, **Add to dashboard** adds the current search as a panel at the bottom of a dashboard, guessing the panel type from the result.

## Panel types

| Type | The search should end with | Example |
|---|---|---|
| Lines / stacked area / bars over time | `| timechart` | `dataset=traefik.access | timechart count() by resource` |
| Single number | `| stats` with one value | `dataset=crowdsec.decision | stats count()` |
| Ranked bars, pie | `| top` or `| stats … by` | `dataset=crowdsec.decision | top limit=10 rule.name` |
| World map | `| stats … by` a 2-letter country code | `dataset=crowdsec.decision | stats count() by source.geo.country_iso_code` |
| Table | anything (first 100 rows) | `dataset=authentik.event action=login_failed | stats count() by user, src` |

**Values are** sets how numbers are shown: plain numbers, durations (nanoseconds, as ECS `event.duration` is; shown as µs/ms/s), bytes, or percentages.

Country maps need country codes on the events. Today CrowdSec decisions and authentik events carry them (`source.geo.country_iso_code`); GeoIP for other sources is on the roadmap.
