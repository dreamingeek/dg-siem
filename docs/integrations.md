# Integrations

An integration pack is a ready-made setup for one kind of system, such as Proxmox. It includes:

- how to get the system's data into DG SIEM: the steps to follow at the source and the agent input to add;
- how to tell the data is arriving;
- dashboards and alert rules for it.

Packs are data only: a YAML file, no code. DG SIEM ships with some built in, and you can add your own.

## Using a pack

Open **Integrations** and choose a pack.

1. **Install** it once for the server. This creates its dashboards and alert rules. The alerts start **switched off**.
2. Choose a tenant and **Turn on for &lt;tenant&gt;**. The setup steps then show the token generated for that tenant.
3. **Add input** puts the pack's input on one of the tenant's agents. The agent picks it up within a minute. You can also paste the input into the agent's config yourself.
4. Follow the steps at the source. The tenant's status changes to **Receiving data** once data arrives.
5. Open the pack's alerts to turn them on and choose who hears about them.

Dashboards and alerts are shared by all tenants, like your own. A dashboard's tenant picker narrows it to one tenant. A pack's alerts run only for the tenants the pack is on for. That way a "stopped sending" alert doesn't fire for clients that don't run that system.

**Turning a pack off for a tenant** stops its alerts there. The agent input stays until you remove it from the agent.

**Removing a pack from the server** turns it off for every tenant and deletes its dashboards and alerts. Any you edited are kept as your own.

### Updates and your edits

When a new DG SIEM version brings a newer version of a pack, the pack shows **Update available**. Updating refreshes the dashboards and alerts you haven't edited. Edited ones are left as they are and marked **edited** on the pack's page.

These count as edits:
- changing a dashboard's name, description, time range or panels;
- changing an alert's name, search, time range, schedule, condition, severity or quiet period.

These don't count as edits:
- turning an alert on or off;
- changing who an alert emails, or whether it opens tickets.

To get a pack's current version of something you edited, delete your copy and choose **Update** (or remove and reinstall the pack).

## Built-in packs

| Pack | What it collects |
|---|---|
| Proxmox VE | Node, VM, container and storage metrics from Proxmox's Metric Server ([details](metrics.md#proxmox-ve)) |

## Writing a pack

A pack is one YAML file. Put your own in the server's packs folder, `/var/lib/dg-siem/packs` by default (setting `Packs__Directory`). Each pack can be either:
- `<name>.yaml` directly in the folder, or
- `<name>/pack.yaml` in its own sub-folder.

With docker compose, the simplest way is to keep them next to your compose file and mount the folder in `docker-compose.override.yml`:

```yaml
services:
  dg-siem-server:
    volumes:
      - ./packs:/var/lib/dg-siem/packs:ro
```

After adding or changing a file, choose **Reload** on the Integrations page. A pack with a mistake isn't offered. The page lists it with the problem, for example the line of a YAML error or the search that doesn't parse. Every search is checked when the pack is read.

```yaml
id: proxmox                   # lower-case letters, digits and dashes; never change it once installed
name: Proxmox VE
version: 1                    # raise it when you change the pack, so installs offer the update
category: Virtualization      # groups packs on the page
description: One sentence about what it collects.
docs: https://example.com/    # optional link to the product's own docs

setup:
  input:                      # optional: the agent input, exactly as in an agent's config
    type: InfluxDb
    port: 8086
    job: proxmox
    tokens: ["{{token}}"]
  steps:                      # what to do at the source, one item per step
    - In Proxmox, open **Datacenter → Metric Server → Add → InfluxDB**.
    - "Port: {{port}}. Token: {{token}}"

receiving:                    # optional: a search that returns rows while data is arriving
  search: '| mstats count(cpustat_cpu) as samples | where samples > 0'
  within: 15m

dashboards:
  - key: overview             # stable id within the pack; lets updates find it after a rename
    name: Proxmox overview
    description: Optional.
    timeRange: -4h            # -15m, -1h, -4h, -24h, -7d or -30d
    panels:
      - title: Node CPU
        kind: timeline        # timeline, timearea, timebars, stat, bars, pie, table, map
        unit: number          # number, duration, bytes, percent
        w: 6                  # optional width on the 12-column grid (and h for height)
        search: '| mstats avg(cpustat_cpu) by host span=5m'

alerts:
  - key: stopped
    name: Proxmox stopped sending metrics
    description: Optional; included in the alert.
    search: '| mstats count(cpustat_cpu) as samples | where samples > 0'
    timeRange: 15m            # how far back each run looks
    schedule: '*/5 * * * *'
    condition: below          # any (any results), above or below (number of results vs threshold)
    threshold: 1
    trigger: once             # or per-result: one alert per row
    severity: high            # low, medium, high, critical
    suppressBy: host          # optional: one alert per value of this field per quiet period
    suppressMinutes: 240
```

Notes:

- **Placeholders.** `{{token}}`, `{{port}}` and `{{tenant}}` work in `setup` only. `{{token}}` is a random token generated for each tenant. Dashboards and alerts are shared by all tenants, so they can't use placeholders.
- **Formatting in steps.** Steps can use `` `code` `` and `**bold**`. Quote a step that contains `: ` so YAML reads it as text.
- **Panel layout.** Panels flow left to right and wrap. Each kind has a default size: stat 3×2, bars 4×4, timelines 8×4, tables 6×4, maps 6×5.
- **Names.** If a dashboard or alert name is already taken, the pack's copy gets the pack's name added, e.g. "Overview (Proxmox VE)".
- **Removing items.** Leaving a dashboard or alert out of a newer version removes it on update, unless it was edited.
