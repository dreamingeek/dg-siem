# Security policy

DG SIEM collects security logs and holds credentials (agent certificates, mail and storage keys), so security reports are taken seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub: the repository's **Security** tab → **Report a vulnerability**. Include what you found, how to reproduce it, the version (shown at the bottom of the Health page, and by `dg-siem-agent --version`), and what an attacker gains.

DG SIEM is maintained by a small team. You'll get an acknowledgement within a week; we'll keep you posted while we fix it, credit you in the release notes if you'd like, and ask you to hold off publishing until a fixed release is out (90 days at most).

## Supported versions

Fixes go into the latest release. Agents update themselves from the server (Administration → Agent updates), so keep both on the latest release.

## Running it safely

- Put the web UI (port 8080) behind a TLS reverse proxy; don't expose it directly.
- Expose the agent port (8443) as raw TCP only: agents authenticate with client certificates, which a TLS-terminating proxy would strip.
- Set strong, unique `POSTGRES_PASSWORD` and `CLICKHOUSE_PASSWORD` values, and don't publish the PostgreSQL or ClickHouse ports.
- Turn on two-factor sign-in for administrators.
- Back up the agent CA and keys (the nightly config backup does this, encrypted with your passphrase).

## Scope

In scope: the server, the agent, the install scripts and the default `deploy/` setup. Out of scope: vulnerabilities in third-party dependencies with no DG SIEM-specific impact (report those upstream), and setups that ignore the guidance above.
