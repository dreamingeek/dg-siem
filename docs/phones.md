# Phones and PBXs

## Asterisk / FreePBX

Install the agent on the PBX (Administration → Agents → **Enroll agent** gives a one-line install command; the PBX must be able to reach the server's agent port) and give it a `File` input for Asterisk's `full` log:

```json
{
  "type": "File",
  "paths": ["/var/log/asterisk/full"],
  "app": "asterisk",
  "multiline": "Pattern",
  "multilineStart": "^\\[\\d{4}-"
}
```

- `multiline: Pattern` keeps a multi-line SIP packet (from `pjsip set logger on`) together as one event: a line starting with `[2026-...` begins an event, anything else belongs to the one above.
- Asterisk writes local time with no zone. The agent stamps each line with the PBX's UTC offset, so times are exact, also when reading old lines with `fromBeginning`.
- The agent runs as `dg-siem-agent`. If it can't read the log, add it to Asterisk's group and restart it: `usermod -aG asterisk dg-siem-agent && systemctl restart dg-siem-agent`.
- Asterisk's syslog channel and rsyslog `imfile` forwarding work too; the parser accepts either.

### What you get

See [the search guide](search.md#asterisk--freepbx) for the datasets. The ones to alert on:

| Search | Means |
|---|---|
| `dataset=asterisk.security outcome=failure` | Someone is guessing passwords or extensions. Internet-facing PBXs see this constantly; alert on volume per address, e.g. `| stats count() as tries by src | where tries > 20` every 15 minutes. |
| `dataset=asterisk.security action=successful-auth NOT src IN (...)` | A login from somewhere other than your sites (needs the security log, below). |
| `dataset=asterisk.registration action=endpoint-unreachable` | A phone dropped off. |
| `dataset=asterisk.log level IN (warning, error) res_pjsip_outbound_registration*` | The trunk can't register (your SIP provider). |

FreePBX's `full` log has the failed-request notices (`auth-failed`, `unknown-account`, `acl-denied`) out of the box. For Asterisk's security events as well (`successful-auth`, `challenge-response-failed`, `invalid-account-id`, ...), add the `security` level to `full` in **Settings → Asterisk Logfile Settings**. The challenge and hash values in those events are never stored.

### SIP packet logging

`pjsip set logger on` logs every packet, so each phone produces a few events a minute (registration refreshes, voicemail NOTIFYs, OPTIONS keep-alives). That's useful for troubleshooting and for an inventory of phone models (`dataset=asterisk.sip | stats latest(ua) by user, src`), but it's mostly noise for security. Either turn it off when you're done (`asterisk -rx "pjsip set logger off"`), or keep it and add a drop rule: dataset `asterisk.sip`, field `sip.method`, regex `^(OPTIONS|NOTIFY)$`.

## FreeSWITCH / FusionPBX / FS PBX

Install the agent on the PBX and tail `freeswitch.log`:

```json
{
  "type": "File",
  "paths": ["/var/log/freeswitch/freeswitch.log"],
  "app": "freeswitch",
  "multiline": "Pattern",
  "multilineStart": "^([0-9a-f-]{36} )?\\d{4}-\\d\\d-\\d\\d "
}
```

- The pattern keeps FreeSWITCH's multi-line messages (registrations, "Can't find user" with its advice) together.
- FusionPBX runs FreeSWITCH as `www-data`. If the agent logs "Access to the path is denied", check `ls -l /var/log/freeswitch` and either add the agent to that group (`usermod -aG www-data dg-siem-agent`) or grant it read access with `setfacl`, then `systemctl restart dg-siem-agent`.

| Dataset | What |
|---|---|
| `freeswitch.security` | `auth-failed` (wrong password for an extension that exists), `unknown-account` ("Can't find user": scanners guessing extensions or using the PBX's IP as the domain), `acl-denied`. With `user`, `sip.domain` and `src`. These are the lines FusionPBX's fail2ban acts on. |
| `freeswitch.registration` | Phones registering (`registered`, `src` = its public address, `freeswitch.contact_private_ip` = its LAN address), auth challenges, and trunks: `gateway-ping-failed`, `gateway-registration-failed` with `freeswitch.gateway` and `sip.status_code`. |
| `freeswitch.call` | `new-channel`, `answered`, `hangup` with `freeswitch.hangup_cause` (`outcome=failure` for causes other than normal clearing, busy, no answer and the like). `freeswitch.uuid` ties a call's lines together. |
| `freeswitch.log` | Everything else, with `freeswitch.channel` when a line names one. |

FusionPBX logs at DEBUG by default: a dozen state-machine lines per call leg. Registrations and challenges are logged at DEBUG too, so keep the level and drop the chatter instead: drop rule with dataset `freeswitch.log`, field `log.level`, equals `debug`.

```
dataset=freeswitch.security outcome=failure | stats count() as tries, dc(user) as extensions by src, country | sort -tries
dataset=freeswitch.registration action=gateway-* outcome=failure
dataset=freeswitch.call action=hangup outcome=failure | top freeswitch.hangup_cause
```

## Desk phones

Coming next.
