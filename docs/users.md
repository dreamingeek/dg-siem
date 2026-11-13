# Users and access

Sign in with a local account. Create the first admin on the server (with docker compose, prefix these with `docker compose exec dg-siem-server dotnet dg-siem-server.dll` instead of `dg-siem-server`):

```bash
dg-siem-server user add you@example.com --admin      # prints a generated password
dg-siem-server user add client@example.com           # a client login...
dg-siem-server user grant client@example.com acme     # ...that can only see tenant acme
dg-siem-server user passwd you@example.com           # reset (also signs out existing sessions)
dg-siem-server user 2fa-reset you@example.com        # lost phone: turn off two-factor for that user
dg-siem-server user 2fa-required on|off              # require two-factor for everyone
dg-siem-server user list
```

Global admins see every tenant; everyone else sees only tenants they've been granted. Five wrong passwords (or codes) lock an account for 15 minutes.

Taking access away (removing admin rights, a tenant or the account, or changing a role) signs that person out of every browser within a minute, open tabs included; they sign in again with what they have left.

**Two-factor sign-in.** Click your email (top right) to open your account page: set up an authenticator app (Microsoft/Google Authenticator, Bitwarden, 1Password…) by QR code, save the 10 recovery codes, and change your password. Signing in then asks for the 6-digit code after the password, with an option to skip it on that browser for 14 days. Admins see who has it on under **Administration → Users**, can reset it for a lost phone, and can require it for everyone; users without it are sent to set it up before they can do anything else.

## Tenant isolation

Two independent layers:

1. **The query compiler** scopes every search to the user's tenants, and all user input is passed as typed parameters.
2. **ClickHouse row policies.** Searches run as a read-only `dgsiem_reader` user. Each tenant has a ClickHouse role whose row policy allows only its rows, and a search activates only the user's tenant roles. With no roles, the reader sees nothing.

The server sets up the reader, roles and policies automatically. The main ClickHouse user needs access management (`CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1`, already set in the compose file). At startup it **self-tests** that the reader sees zero rows without roles. If setup or the test fails, search is disabled with an explicit error rather than running unprotected. Ingest is unaffected.

The API takes the same session cookie:

```bash
curl -s -X POST http://dg-siem:8080/api/v1/search -H 'Content-Type: application/json' -b cookies.txt \
  -d '{"query":"dataset=unifi.firewall | top src","earliest":"-24h","latest":"now","tenants":["acme"]}'
```
