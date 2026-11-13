# Threat intel

Threat intel marks every event to or from an address on a list of known-bad addresses (botnet controllers, criminal networks, your own list) as it arrives, so you can search for those events and alert on them.

It's **off by default**. Turn it on under **Administration → Features**. While it's off, DG SIEM downloads nothing, marks nothing, and the Threat intel page and its ready-made alerts are hidden. Turning it off later stops both; events marked earlier keep their marks.

## Feeds

**Administration → Threat intel** lists the feeds. Each install downloads them straight from their publishers, on the schedule below, under the publisher's terms; DG SIEM doesn't redistribute any list. Read the terms (linked on the page) before using a feed for clients.

| Feed | What's on it | Updated | On at first |
|---|---|---|---|
| Spamhaus DROP and DROPv6 | IP ranges run by spammers and criminal networks ("Do Not Route Or Peer"). Very few false positives. | Daily (the publisher asks for no more than hourly) | Yes |
| Feodo Tracker (abuse.ch) | Botnet command-and-control servers. Published as CC0, free for commercial use. | Hourly | Yes |
| ThreatFox (abuse.ch) | Command-and-control servers of current malware, from the last two days; DG SIEM keeps each address for 30 days after it was last seen. abuse.ch's terms say commercial use may need a paid subscription through Spamhaus. | Hourly | No |
| Tor exit nodes | Addresses Tor traffic leaves from. Not malicious in itself; a sign-in from one is worth a look. | Every 6 hours | No |

**Add a feed** takes any list at a web address with one address or CIDR range per line (`#` comments allowed); it's downloaded every 6 hours.

Each download is saved in `/var/lib/dg-siem/threatintel` (the `dg-siem-data` volume), so a restart doesn't wait for downloads, and a feed that fails to download keeps using its last copy. The Health page warns when a feed has been failing for more than three of its update intervals.

## Your list

Addresses and ranges you add yourself, one per line, with a note on each ("brute-forced the VPN"). Your list is checked first, so your note is what an event shows even when a feed lists the same address.

## How events are marked

Each event's `source.ip` and `destination.ip` are looked up as it arrives. A match adds:

| Field | Shortcut | Value |
|---|---|---|
| `threat.feed.name` | `threat_feed` | The list it's on: `Spamhaus DROP`, `Feodo Tracker`, `Your list` |
| `threat.enrichments.matched.field` | `threat_on` | `destination.ip` when something reached out to it, `source.ip` when it reached in |
| `threat.enrichments.indicator.ip` | `threat_ip` | The listed address |
| `threat.enrichments.indicator.description` | `threat_reason` | Why it's listed (and the listed range, for a range) |

When both addresses are listed, the destination wins: a device reaching out to a known-bad server matters most.

Searches:

```
threat_feed=*                                                   every marked event
threat_on=destination.ip | stats count() by src, dst, threat_feed, threat_reason
threat_on=source.ip action=accept                               inbound from a listed address that got through
```

Events are checked when they arrive. When a list changes, events already stored aren't re-checked.

## Alerts

With threat intel on, **Alerts → Add ready-made alerts** offers two more:

- **Traffic to a known-bad address** (High): a device inside reached out, or tried to, to a listed address. Even a blocked attempt means something inside is trying.
- **Sign-in from a known-bad address** (Critical): a successful sign-in from a listed address (Windows, authentik, the PBX). Tor exit nodes count when that feed is on.

Inbound traffic from listed addresses isn't alerted on by default: it's mostly scanning your firewall already blocks. Search for it, or chart it on a dashboard.

**Check an address** on the Threat intel page shows what an address is listed on right now.
