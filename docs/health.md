# Health

**Administration → Health** shows whether everything that has to work for logs to arrive, be kept and raise alerts is working, and what to fix when it isn't. It refreshes every minute while it's open, and an alert email's link opens it for that tenant (`admin/health?tenant=acme`).

## Checks

| Check | Problem when |
|---|---|
| Event store | ClickHouse doesn't answer, or the event disk is under 15% free (under 8% is serious) |
| Ingest | Writing to ClickHouse is failing, events are piling up in the server's queue, or agents check in but nothing has been stored for 15 minutes |
| Log sources | A regular source went quiet (below) |
| Agents | An agent stopped checking in (30 minutes), has had events waiting over 30 minutes, or lost events because its buffer filled |
| Alerts | An alert's last run failed (a bad query, ClickHouse down) |
| Email | Alerts are set to email but no mail server is set up |
| Backups | Backups are off, the last one failed, or the last good one is over 36 hours old |
| Cold storage | Cold storage is on but not working (no bucket, ClickHouse refused the settings) |
| Agent certificates | An agent's certificate is within 14 days of expiry: agents renew 30 days ahead, so renewal is failing |
| GeoIP | No database loaded, or the last update failed |
| Threat intel | (Only when it's on) A feed has failed for over three of its update intervals, or every feed is off |

## Log sources

A source is one tenant's host sending one dataset: `unifi.firewall` from `gw1`, `asterisk` from `pbx`. The host is `host.name`, or the sending device's address when the log names no host.

Each source is judged against its own last 8 days of activity (hourly, by when the server received its events, so a device with a wrong clock still counts as sending):

- **Usually silent at most** is the longest it went without events in those 8 days.
- It's **Quiet** once it has been silent for about twice that, at least 2 hours and at most 3 days. A firewall that logs all the time is quiet after about two silent hours; a PBX that's silent 6 hours every night only after about 14; a server that's quiet every weekend after 3 days.
- **New** sources (first seen under 2 days ago) and **Occasional** ones (events in fewer than 24 of the hours) are listed but never called quiet.
- **Last 24 h** shows the events received, and how far that is from a usual day when it's off by half or more.

A retired device keeps showing as quiet until its activity ages out (35 days). **Ignore** it to leave it out of the check and the alert; **Watch again** undoes that.

## Agents

From agent 0.5.0, each agent reports its disk buffer on every config poll (once a minute):

- **Waiting to send**: events buffered on the agent and how long the oldest has waited. A backlog clears on its own after a network blip; one that keeps growing while the agent checks in means events aren't getting through.
- **Lost**: events the agent dropped since it started because its queue or buffer was full (the oldest are dropped first). Raise `Agent:MaxBufferBytes` on a host that loses events during outages.
- **Rejected**: batches the server refused, set aside in the agent's `buffer/rejected` folder.

Agents before 0.5 show `–` until they update.

## When ClickHouse is down

The server keeps the batch it was writing and retries it (after 2, 4, 8, 16, then every 30 seconds). Meanwhile it answers agents' deliveries with 503, so they keep new events in their disk buffers and resend them once ClickHouse is back. Nothing is lost while the agents' buffers have room (2 GB each by default). Health shows **Ingest** failing with ClickHouse's error, and each agent's backlog growing.

## Alerts

Two ready-made alerts watch this for you. Turn them on with **Turn on health alerts** on the Health page, or under **Alerts → Add ready-made alerts → Health**:

- **A log source went quiet** checks every 15 minutes.
- **An agent is offline or falling behind** checks every 5 minutes.

Each sends one alert per tenant listing everything that's wrong, so an agent going down sends one email, not one per source behind it. While the same things stay wrong the alert stays quiet for its repeat period (24 and 12 hours); anything newly wrong alerts again. They email whoever turned them on and open an AlgaPSA ticket (High), like the other ready-made alerts; change that in the editor.
