# Storage: retention and cold tier

**Administration → Storage** sets how long events are kept, moves older events to an S3-compatible bucket, and shows what each source costs.

## Retention

Each event is stamped with the days it's kept when it arrives, and ClickHouse deletes it when they're up (row by row, during merges, so a 30-day firewall event and a 365-day sign-in can share a day's data).

The rule that decides is the most specific one that matches the event:

1. a rule for the event's tenant beats a rule for all tenants;
2. within those, an exact dataset (`windows.security`) beats a prefix (`unifi.*`), a longer prefix beats a shorter one, and `*` comes last;
3. events no rule matches get **Everything else**.

The suggested rules (loaded until you save your own; **Suggested rules** brings them back):

| Kept | Datasets |
|---|---|
| 365 days | `windows.security`, `windows.defender`, `windows.powershell`, `authentik.event`, `asterisk.security`, `freeswitch.security`, `crowdsec.decision`, `crowdsec.alert` |
| 30 days | `unifi.firewall`, `unifi.vpn`, `traefik.access`, `asterisk.sip`, `freeswitch.log`, `crowdsec.lapi`, `authentik.http`, `authentik.tasks` |
| 120 days | everything else |

**Save** applies to events from then on. **Apply to stored events** re-stamps what's already stored, in the background; where the new retention is shorter, events past it are deleted at ClickHouse's next merge (usually within hours). That can't be undone.

Searches go back a year at most from the time picker (**Last year**); longer retention is still searchable with a custom range.

**What each source costs** lists the last 7 days per tenant and dataset: events and raw size per day, how long they're kept, and the raw size that adds up to. ClickHouse stores roughly a fifth to a tenth of that after compression. It's the place to find what to shorten or drop (Drop rules).

## Cold tier (S3)

Events older than N days can move to an S3-compatible bucket (Backblaze B2, Wasabi, MinIO, AWS) and stay searchable: searches read both tiers, older ranges are slower the first time and then cached locally (10 GB cache). They're deleted from the bucket when their retention is up.

1. Create a bucket (private) and an application key limited to it, with read, write, list and delete. Use the bucket, or a folder in it, only for DG SIEM: ClickHouse names the objects itself.
2. **Administration → Storage → Cold storage**: enter the bucket URL with a folder, ending in `/`, and the keys, then **Test and save**. ClickHouse writes and reads a small test file (`dg-siem-connection-test.csv`) in the folder first, so a wrong URL or key is reported straight away.

   Bucket URLs: B2 `https://s3.<region>.backblazeb2.com/<bucket>/<folder>/` (the region is in the bucket's endpoint), Wasabi `https://s3.<region>.wasabisys.com/<bucket>/<folder>/`, MinIO `http://host:9000/<bucket>/<folder>/`, AWS `https://<bucket>.s3.<region>.amazonaws.com/<folder>/`.
3. Switch on **Move older events to the bucket**, choose after how many days, and **Save** under Retention. The events table switches to the tiered policy and data older than that starts moving in the background; **Where events are** shows each tier.

There's no ClickHouse restart. The server writes the bucket into a config file in a folder it shares with ClickHouse (the `clickhouse-conf` volume, ClickHouse's `conf.d`) and tells ClickHouse to reload. The keys are kept in PostgreSQL, encrypted like the other passwords, so config backups include them, and the file is rewritten at startup if the volume is ever recreated.

Notes:

- **Changing keys** (**Change keys**) applies straight away. **Changing the bucket** isn't possible from the page once ClickHouse is using it: ClickHouse only switches a bucket on restart, which would strand the events already there. To move, switch cold storage off, move the data back (`ALTER TABLE dgsiem.events MOVE PARTITION ... TO VOLUME 'default'`), then change the bucket with ClickHouse stopped.
- "After" must be shorter than the retention, or nothing would ever move.
- If the local disk drops under 10% free, ClickHouse moves data to the bucket early (newest included) rather than running out of space; the Storage page warns when the disk is getting full.
- Switching cold storage off stops further moves; what's in the bucket stays there until its retention is up.
- If the bucket is unreachable, ClickHouse still starts and everything on local disk keeps working; searches over older ranges fail until it's back.

### Moving from docker-compose.s3.yml

Earlier versions set the bucket up in `.env` with `docker-compose.s3.yml`. The page shows **The bucket is set up in docker-compose.s3.yml** for those.

1. Pull the update and `docker compose up -d` (the overlay still in `COMPOSE_FILE`).
2. Under **Cold storage**, enter the same bucket URL and keys as `DGSIEM_S3_*` in `.env` and **Test and save**. If events are already in the bucket, the server refuses a URL whose folder doesn't hold them.
3. Take `docker-compose.s3.yml` out of `COMPOSE_FILE` (or delete the line if it was the only addition), delete the `DGSIEM_S3_*` lines, and `docker compose up -d`.

The disk, cache and policy keep the same names and paths, so the events already in the bucket carry on as they were.
