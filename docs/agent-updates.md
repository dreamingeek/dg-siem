# Installing and updating agents

The server hands out agent versions you upload: to new machines through a one-line install command, and to running agents as automatic updates.

## Upload a version

**Administration → Agent updates → Upload a version.** Upload the agent package (`dg-siem-agent-…-linux-x64.tar.gz`, `…-win-x64.zip`, as built by CI or a release) or the agent binary itself. The server reads the platform (Linux x64/ARM64, Windows x64) and the version from the file, so there's nothing to fill in; it only accepts agents from 0.4.0 on, which carry their version inside them.

From the binary, the server builds an install package with its own copy of the install scripts and systemd units. The three newest versions per platform are kept (`AgentPackages:Directory`, default `/var/lib/dg-siem/agent-packages` on the data volume).

## Install on a new machine

**Agents → Enroll an agent** creates a token and shows one command per uploaded platform:

- **Linux** (as root): `curl` downloads the package from the agent port with the token, `sha256sum -c` checks it against the SHA-256 written into the command, then `install.sh` installs and enrolls.
- **Windows** (Administrator PowerShell): the same with `WebClient`, `Get-FileHash` and `install.ps1`.

The agent port's certificate comes from DG SIEM's own CA, which the machine doesn't trust yet, so the download skips the certificate check and relies on the checksum instead. The command itself comes from the UI, so a tampered download fails the check and nothing is installed. The download also needs an unused enrollment token, so the agent isn't public.

## Automatic updates

With **Automatic updates** on (the default), every agent from 0.4.0 on checks every 15 minutes for a newer version for its platform. It downloads it over its mTLS connection, checks size and SHA-256 against the server, runs the new binary's `--version`, and only then swaps it in:

- **Windows:** the service (LocalSystem) renames the running `dg-siem-agent.exe` aside, moves the new one into place and restarts itself. The old file is deleted on the next start.
- **Linux:** the service runs unprivileged and can't write `/usr/local/bin`. It creates `/var/lib/dg-siem-agent/update/requested`; `dg-siem-agent-update.path` (systemd) then starts `dg-siem-agent-update.service`, which runs `dg-siem-agent self-update` as root. That fetches and verifies the update itself with the agent's certificate, so the unprivileged agent can ask for an update but never supplies what root installs. History: `journalctl -u dg-siem-agent-update`.

Agents never downgrade. To pull a bad version, **Remove** it: new installs and agents not yet on it get the next newest, and agents already on it stay there until you upload a fixed one. To stage a version, turn automatic updates off: new installs get it, running agents stay put.

The Agents page shows `→ 0.4.1` next to agents with an update pending, and `(manual)` next to agents older than 0.4.0.

## Agents older than 0.4.0

They don't have the updater. Upgrade each once, then they update themselves:

1. Upload 0.4.0 or later on **Agent updates**.
2. **Agents → Enroll an agent**: create a token (any tenant) and copy the command for the platform.
3. Run it on each older agent. `install.sh` / `install.ps1` see the machine is already enrolled and only upgrade it (and on Linux install the update units); the token isn't used up, so the same command works for every machine until it expires.
