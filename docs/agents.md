# Collecting logs

How to connect a site: expose the agent port, create a tenant and an install token, install `dg-siem-agent`, and choose what it collects.

## 1. Server side

The server listens on two ports:

| Port | What | How to expose it |
|---|---|---|
| 8080 | Web UI | Behind your reverse proxy (NPM, Traefik, Pangolin HTTP resource) |
| 8443 | Agent API, with its own TLS and client certificates | **Raw TCP only** (e.g. a Pangolin TCP resource or a plain port forward). A TLS-terminating proxy strips the agents' certificates and enrollment fails. |

On first start the server creates a private CA in `/var/lib/dg-siem/pki` (the `dg-siem-data` volume). **Back it up**: if it is lost, every agent has to re-enroll.

Set `DGSIEM_AGENT_HOSTNAME` in `.env` to the name agents will use for port 8443 (e.g. `siem-agents.example.com`). The agent-port certificate is issued for that name, and is re-issued automatically if you change it.

## 2. Add a tenant and an enrollment token

```bash
docker compose exec dg-siem-server dotnet dg-siem-server.dll tenant add acme "Acme"
docker compose exec dg-siem-server dotnet dg-siem-server.dll token create acme --name acme-log-col
# → dgs1_<secret>_<ca-fingerprint>   (single use, expires in 24h; --hours to change)
```

The token carries the CA's fingerprint, so a new agent can verify it is talking to *your* server before it sends anything.

## 3. Install the agent at the site

On a Debian/Ubuntu LXC or Raspberry Pi (x64 or arm64):

```bash
curl -fsSL https://raw.githubusercontent.com/dreamingeek/dg-siem/main/deploy/agent/install.sh | \
  sudo bash -s -- --server https://siem-agents.example.com:8443 --token dgs1_... --name acme-log-col
```

The agent is a single native binary running as the unprivileged `dg-siem-agent` user (with permission to bind ports 514/6514). Data waiting to ship is buffered under `/var/lib/dg-siem-agent/buffer` (2 GB cap by default), so a server or WAN outage doesn't lose logs. Certificates renew automatically 30 days before they expire.

## 4. Configure the agent's inputs (centrally)

Every agent starts with syslog on UDP/514 and TCP/514. Change it from the server, and the agent picks it up within a minute:

```bash
cat > acme.json <<'JSON'
{
  "inputs": [
    { "type": "SyslogUdp", "port": 514 },
    { "type": "SyslogTcp", "port": 514 },
    { "type": "SyslogTls", "port": 6514 }
  ],
  "sourceHints": [
    { "source": "192.168.1.1",   "dataset": "unifi" },
    { "source": "10.20.30.0/24", "dataset": "sip" }
  ]
}
JSON
docker compose exec -T dg-siem-server dotnet dg-siem-server.dll agent config set acme/acme-log-col - < acme.json
```

`sourceHints` tell the server which parser to use for a sender. UniFi's CEF output ("SIEM Server" integration) is recognised without a hint; the older iptables-style firewall lines need `dataset: unifi`.

### Tailing log files

A `File` input reads log files on the agent's machine, so nothing needs to forward them:

```json
{ "type": "File", "paths": ["/var/log/nginx/*.log"], "app": "nginx" }
{ "type": "File", "paths": ["/opt/pangolin/config/traefik/logs/access.log"], "app": "traefik-access" }
{ "type": "File", "paths": ["/var/log/myapp/app.log"], "multiline": "Indented", "fromBeginning": true }
{ "type": "File", "paths": ["/var/log/asterisk/full"], "app": "asterisk", "multiline": "Pattern", "multilineStart": "^\\[\\d{4}-" }
```

- `paths`: absolute paths; `*` and `?` work in the file name (not in folder names). Compressed rotations (`.gz`, `.zip`) are skipped.
- `app`: the app name events carry (`process.name`); defaults to the file name. Lines are wrapped like forwarded syslog (this host, that app), so the usual parsers apply: a Traefik or authentik JSON line from a file parses exactly as it would over syslog. The path is kept as `log.file.path`.
- Files already there when the input starts are read from their end; set `fromBeginning` to read them whole. Files that appear later (e.g. after rotation) are read from the start.
- Rotation by rename (logrotate's default) and copy-truncate are both handled, and the old file is read to its end first. Positions are saved in `file-positions.json` in the agent's data folder, so restarts neither skip nor repeat lines.
- `multiline: "Indented"` joins lines that start with a space or tab to the line above (stack traces). `multiline: "Pattern"` starts an event at each line matching the `multilineStart` regular expression and joins the rest to it (Asterisk's SIP packets, Java logs).
- Lines are stamped with the agent host's UTC offset, so logs that write local time without a zone (Asterisk, Apache) are placed exactly. See [phones.md](phones.md) for FreePBX.
- Lines longer than 64 KB are cut. The agent runs as the `dg-siem-agent` user, which the installer adds to the `adm` group so it can read most of `/var/log`; for other files, make sure that user can read them. The service can't see `/home`, `/root` or `/tmp` (systemd hardening); to tail files there, add a drop-in with `systemctl edit dg-siem-agent`: `[Service]` / `ProtectHome=read-only`.

### Windows

The agent also runs on Windows as a service and reads the event logs (Security, System, Application, Sysmon, PowerShell, Defender by default), resuming from a bookmark per log. **Enroll agent** shows a PowerShell install command next to the Linux one; see [windows.md](windows.md).

### HTTP Event Collector (HEC)

A `Hec` input makes the agent a Splunk-compatible HTTP Event Collector, so anything that can send to Splunk (Docker's `splunk` log driver, Vector, Fluent Bit, scripts, apps with a Splunk logger) can send to DG SIEM. The **Edit inputs** dialog generates a token for you.

```json
{ "type": "Hec", "port": 8088, "tokens": ["0b6c4f9e-2a8d-4c1b-9f0e-5d7a3b2c1e4f"] }
{ "type": "Hec", "port": 8088, "tokens": ["..."], "tls": true, "dataset": "myapp" }
```

```bash
curl -H "Authorization: DGSIEM <token>" http://agent:8088/services/collector/event \
  -d '{"event": "backup finished", "sourcetype": "backup", "host": "nas01"}'
curl -H "Authorization: DGSIEM <token>" "http://agent:8088/services/collector/raw?sourcetype=myapp" --data-binary @app.log
```

- Endpoints: `/services/collector/event` (JSON events, several per request), `/services/collector/raw` (one event per line; `host`, `source` and `sourcetype` in the query string) and `/services/collector/health`. Bodies can be gzipped (up to 16 MB).
- The token goes in `Authorization: DGSIEM <token>` (or `Bearer`, Basic auth as the password, or `?token=`). Clients built for other HEC servers send their own fixed scheme, and that works too, so they need no changes. Tokens must be at least 16 characters; list several to rotate. Replies use Splunk's codes, so clients log meaningful errors.
- `tls: true` serves HTTPS with the agent's certificate from the DG SIEM CA; give clients `ca.crt.pem` from the agent's data folder, or turn off verification on a trusted LAN.
- A string event is parsed like any other log line, so a Traefik or syslog line sent over HEC lands in its usual dataset. Docker's `{"line": ...}` is unwrapped, with `docker.stream` and `docker.tag`. A JSON object is flattened into fields (`http.request.method`), and common names map to the ECS columns: `msg` → `message`, `level` → `log.level`, `user` → `user.name`, `client_ip` → `source.ip`, `action` → `event.action`.
- `event.dataset` is the input's `dataset`, else the sourcetype (`docker:web` → `docker.web`), else `hec`. HEC `time` and `host` fill in when the line has none. `source`, `sourcetype`, `index` and `fields` are kept as `hec.source`, `hec.sourcetype`, `hec.index` and plain fields. Indexes don't route anything: each agent's events go to its tenant.

## Managing agents

Upload agent versions on **Administration → Agent updates**. New machines then install with one command from **Enroll an agent**, and agents from 0.4.0 on update themselves when a newer version is uploaded. See [agent-updates.md](agent-updates.md).

Everything below is also in the UI under **Administration** (global admins only): Agents (enroll with a copy-paste install command, edit inputs, revoke), Tenants, Users and Drop rules. Set `Server__AgentPublicUrl` (e.g. `https://siem-agents.example.com:9443`) so the install command uses the address your sites reach.

```bash
dg-siem-server agent list                       # name, version, cert expiry, last seen
dg-siem-server agent revoke acme/acme-log-col     # blocked within 30s; it keeps its buffered data
dg-siem-server agent config get acme/acme-log-col
```

To move an agent to a rebuilt or new machine, create a token **for that agent's name** (`token create acme --name acme-log-col`, or fill in the name under **Enroll an agent**) and run the installer or `dg-siem-agent enroll ...` with that name. It gets a new certificate and keeps its server-side config. A token without a name can only enroll new agents, and a revoked agent has to be restored (or deleted and enrolled afresh) first.
