# Backups

**Administration → Backups** backs the server up every night into a folder on its host:

| File | Written by | Holds | Encrypted |
|---|---|---|---|
| `config/dg-siem-config-<date>.dgsb` | the server | the agent certificate authority, the sign-in (data-protection) keys, and the whole PostgreSQL database: tenants, users, agents, alerts, dashboards, settings | yes, AES-256-GCM with the backup passphrase |
| `events/events-<date>-full.zip`, `-diff.zip` | ClickHouse (`BACKUP TABLE`) | every stored event, including any in the S3 cold tier | no |

Event backups are **full** every 7 days (configurable) and **differential** in between: each differential holds what changed since the last full one, so restoring needs at most two files. Backups older than the retention you set (30 days by default) are deleted; a full backup is kept for as long as a kept differential needs it, the latest full one is never deleted, and the newest 3 config backups are always kept.

The folder is on the same machine as the server. **Copy it somewhere else** (a NAS, another host, offsite storage) or it won't survive losing the server: an rsync or your backup software over `${DGSIEM_BACKUP_DIR}` after the nightly run is enough.

## Set up

In `deploy/` on the server:

1. Pick a passphrase and put it in `.env`, then save a copy in your password manager. **Config backups can't be restored without it.**

   ```bash
   echo "DGSIEM_BACKUP_PASSPHRASE=$(openssl rand -base64 24)" >> .env
   grep DGSIEM_BACKUP_PASSPHRASE .env    # copy this into your password manager
   ```

2. Optionally pick where the backups go with `DGSIEM_BACKUP_DIR` in `.env` (default `./backups`, next to `docker-compose.yml`). The `dg-siem-init` container creates `config/` and `events/` there with the right owners each time the stack starts (the server runs as uid 1654, ClickHouse as uid 101).

3. Pull the update and recreate the stack (ClickHouse needs `clickhouse/backups.xml` mounted):

   ```bash
   git pull && docker compose up -d --build
   ```

4. Open **Administration → Backups**. Any setup problem shows at the top. Set the time (in the time zone from **Notifications → General**) and press **Back up now** to check it works.

From the command line: `dg-siem-server backup now` and `dg-siem-server backup list`.

## Restore

The usual case is rebuilding the server: a new LXC with the stack installed, and the backup folder copied back.

1. Install DG SIEM **at the same version** the backup was made with (the restore refuses a different database schema), set the same `DGSIEM_BACKUP_PASSPHRASE` in `.env`, put the backups in `${DGSIEM_BACKUP_DIR}`, and start the stack once so the databases are created: `docker compose up -d`.

2. Stop the server, leaving ClickHouse and PostgreSQL running:

   ```bash
   docker compose stop dg-siem-server
   ```

3. Restore the newest config backup and, with `--events`, the newest event backup (a differential pulls in its full one by itself):

   ```bash
   docker compose run --rm dg-siem-server backup restore dg-siem-config-20261112-0815.dgsb --events events-20261112-0815-diff.zip
   ```

   This replaces everything in PostgreSQL (in one transaction: all or nothing), writes the CA and keys back, then restores the events. Events only go into an **empty** events table, because restoring into one that has data would duplicate it. Leave `--events` off to restore just the configuration (for example on a server that still has its events).

4. Start the server: `docker compose up -d`. Agents reconnect with their existing certificates; sign-ins carry on.

Events received between the backup and the restore are still buffered on the agents (up to their disk buffer size), so they arrive once the server is back.

## Notes

- Event backups include data in the cold tier, so they're as large as everything you store. If that's too much for the backup disk, turn off **Include events** and rely on the S3 bucket's own versioning or replication for older events.
- The config backup is encrypted with a key derived from the passphrase (PBKDF2-SHA256, 600,000 rounds). Changing the passphrase applies to new backups; old ones still need the old passphrase.
- To restore one table's worth of events somewhere else for a look, ClickHouse can do it directly: `RESTORE TABLE dgsiem.events AS dgsiem.events_restored FROM Disk('backups', 'events-….zip')`.
