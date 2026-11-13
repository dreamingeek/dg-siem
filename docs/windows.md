# Windows

The agent runs on Windows as the `dg-siem-agent` service and reads the event logs. It's the same agent as on Linux (a single native `dg-siem-agent.exe`), so it can also tail files, listen for syslog or run a HEC input.

## Install

1. Once: upload the Windows package (`dg-siem-agent-…-win-x64.zip`) on **Administration → Agent updates**.
2. **Administration → Agents → Enroll an agent** gives a one-line command for Windows. Paste it into an Administrator PowerShell on the machine: it downloads the agent from the server, checks its SHA-256 and runs `install.ps1`. (Without an uploaded version, copy the zip to the machine and run `install.ps1 -Server … -Token …` from the unpacked folder.)
3. The agent shows on the Agents page within a minute with the Windows default inputs.

`install.ps1` copies the agent to `C:\Program Files\DG SIEM Agent`, keeps its key, certificate and buffer in `C:\ProgramData\DG SIEM\Agent` (SYSTEM and Administrators only), enrolls, and creates an automatic service running as LocalSystem that restarts itself after a crash. It runs fine from an RMM (Datto RMM component, as SYSTEM).

**Upgrade:** automatic from 0.4.0 on: upload a new version on **Agent updates** and the agent installs it within 15 minutes ([docs/agent-updates.md](agent-updates.md)). By hand: run `.\install.ps1` again from the new package, without `-Server` and `-Token`. Enrollment, config and the read position in each log are kept.

**Uninstall:** `Stop-Service dg-siem-agent; sc.exe delete dg-siem-agent`, then delete the two folders.

The agent's own warnings and errors go to the Application log (source `dg-siem-agent`).

## What it reads

A Windows agent gets this input when it enrolls; change it under **Edit inputs**:

| Log | Filtered at the source | Why |
|---|---|---|
| `Security` | Filtering Platform connection events (5152, 5156–5158) and handle closes (4658, 4690) | Sign-ins, failed sign-ins, lockouts, account and group changes, new services and scheduled tasks, cleared logs |
| `System`, `Application` | | Service installs and crashes, unexpected shutdowns, application crashes, installs |
| `Microsoft-Windows-Sysmon/Operational` | | Process, network, DNS, file and registry activity, if Sysmon is installed (otherwise checked again every 5 minutes) |
| `Microsoft-Windows-PowerShell/Operational` | Only 4104 (script blocks) | Windows logs suspicious script blocks even without policy; enable Script Block Logging for all of them |
| `Microsoft-Windows-Windows Defender/Operational` | Hourly health reports (1150, 1151) | Detections, actions, real-time protection turned off, signature failures |

```json
{ "type": "WindowsEventLog", "channels": [
    { "name": "Security" },
    { "name": "Microsoft-Windows-TaskScheduler/Operational" },
    { "name": "Microsoft-Windows-PowerShell/Operational", "query": "*[System[(EventID=4104)]]" }
] }
```

- `channels`: any log in Event Viewer, by its full name (Properties → Full Name). Leave the list out for the defaults above.
- `query`: an event-log XPath filter, as in Event Viewer's *Filter Current Log → XML*. Windows applies it, so filtered events never leave the machine.
- `fromBeginning: true` reads what's already in each log the first time (otherwise only new events). After that the agent keeps a bookmark per log and resumes exactly where it stopped, including across reboots and upgrades.

Each event is sent as Windows renders it (the XML plus the message text), so the server can map it fully.

## Searching

Datasets: `windows.security`, `windows.system`, `windows.application`, `windows.sysmon`, `windows.powershell`, `windows.defender`, and `windows.<log>` for others (`Microsoft-Windows-TaskScheduler/Operational` → `windows.taskscheduler`). Fields follow Winlogbeat (`winlog.event_id`, `winlog.channel`, `winlog.event_data.*`) plus ECS (`user.name`, `source.ip`, `process.*`), so searches and Sigma rules written for Winlogbeat translate directly.

| Action (`action=`) | Events |
|---|---|
| `logged-in`, `logon-failed`, `logged-out`, `logged-in-explicit`, `logged-in-special` | 4624, 4625, 4634/4647, 4648, 4672. `winlog.logon.type` (Interactive, Network, RemoteInteractive…), `src`, and for failures `winlog.logon.failure.reason` (Wrong password, No such user, Account locked out…) |
| `locked-out-user-account`, `unlocked-user-account`, `added-user-account`, `deleted-user-account`, `enabled-/disabled-user-account`, `reset-password`, `changed-password` | 4740, 4767, 4720, 4726, 4722/4725, 4724, 4723. `user` is who did it, `user.target.name` who it was done to |
| `added-member-to-group`, `removed-member-from-group` | 4728/4732/4756, 4729/4733/4757, with `group.name` |
| `credential-validated`, `kerberos-*` | 4776 (NTLM), 4768/4769/4771 on domain controllers |
| `created-process` | 4688 (with command line if "Include command line in process creation events" is on) |
| `service-installed`, `created-scheduled-task`, `audit-log-cleared`, `log-cleared` | 4697/7045, 4698, 1102, 104 |
| `process-created`, `network-connection`, `dns-query`, `file-created`, `registry-value-set`… | Sysmon 1, 3, 22, 11, 13… with `process.*`, `process.hash.sha256`, `dns.question.name` |
| `script-block-logged` | PowerShell 4104, text in `powershell.file.script_block_text` |
| `malware-detected`, `malware-action-taken`, `real-time-protection-disabled` | Defender 1116, 1117, 5001, with `threat.name`, `file.path` |

```
dataset=windows.security action=logon-failed | stats count() as tries, dc(user) as accounts by src, host | sort -tries
dataset=windows.security action=locked-out-user-account | table @timestamp, host, user, source.domain
dataset=windows.security action=added-member-to-group group.name IN ("Domain Admins", "Administrators", "Enterprise Admins")
dataset=windows.security action=logged-in winlog.logon.type=RemoteInteractive NOT src=10.0.0.0/8
dataset=windows.defender event.kind=alert | table @timestamp, host, user, threat.name, file.path, defender.action
action IN (audit-log-cleared, log-cleared, real-time-protection-disabled, service-installed)
```
