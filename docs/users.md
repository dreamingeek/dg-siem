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
dg-siem-server user sso-unlink you@example.com      # remove their single sign-on link
dg-siem-server sso off                              # turn single sign-on off (then restart the server)
```

Global admins see every tenant; everyone else sees only tenants they've been granted. Five wrong passwords (or codes) lock an account for 15 minutes.

Taking access away (removing admin rights, a tenant or the account, or changing a role) signs that person out of every browser within a minute, open tabs included; they sign in again with what they have left.

**Two-factor sign-in.** Click your email (top right) to open your account page: set up an authenticator app (Microsoft/Google Authenticator, Bitwarden, 1Password…) by QR code, save the 10 recovery codes, and change your password. Signing in then asks for the 6-digit code after the password, with an option to skip it on that browser for 14 days. Admins see who has it on under **Administration → Users**, can reset it for a lost phone, and can require it for everyone; users without it are sent to set it up before they can do anything else.

## Single sign-on (Authentik)

Sign in through Authentik, or any other OpenID Connect provider, instead of a password and authenticator code. The provider asks for the second factor, so a single sign-on session counts as two-factor done, even when two-factor is required for everyone.

Accounts are still added in **Administration → Users**: nobody gets in just by having an account at the provider. Each person links their provider account once, and from then on the provider's account ID identifies them.

**In Authentik:**

1. **Applications → Applications → Create with provider**. Name it DG SIEM and choose **OAuth2/OpenID Provider**.
2. Client type **Confidential**. Under **Redirect URIs**, add a **Strict** one: the address shown on DG SIEM's Users page, `https://<your DG SIEM address>/signin-oidc`.
3. Keep the default scopes (openid, email, profile). Save, then copy the provider's **Client ID**, **Client Secret** and **OpenID Configuration Issuer** (e.g. `https://auth.example.com/application/o/dg-siem/`).
4. Bind the application to the group or users who should reach DG SIEM.

**In DG SIEM:**

1. Behind a reverse proxy, set the **public URL** first (Administration → Notifications, e.g. `https://dg-siem.example.com`). DG SIEM sends people back to that address; without it, the redirect URI would say `http://` and the provider would refuse it.
2. On **Administration → Users → Single sign-on**, paste the issuer, client ID and secret, name the button (e.g. *DG Auth*) and turn it on. Saving checks that this server can read the provider's settings, so you'll see straight away if the address is wrong or the server can't reach it.
3. Each person signs in with their password once, opens **their account page** (their email, top right) and chooses **Link your Authentik account**. After that, **Sign in with …** on the sign-in page takes them straight in.

An account also links by itself on its first single sign-on when the provider marks the email as verified and it matches a DG SIEM account. Authentik 2025.10 and later send `email_verified: false` unless you add a scope mapping for it, so linking from the account page is the usual way.

**Password sign-in** can stay open to everyone, or be limited to global admins as a way in if the provider is down. If the provider is down and you're locked out, run `dg-siem-server sso off` on the server and restart it.

Admins see each person's linked account on the Users page and can unlink it. Unlinking signs that person out everywhere within a minute. The client secret is stored encrypted. Sign-ins use the code flow with PKCE.

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
