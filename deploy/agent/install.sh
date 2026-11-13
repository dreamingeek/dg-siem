#!/usr/bin/env bash
# Installs (or upgrades) the DG SIEM agent on a Linux host (Debian/Ubuntu LXC, Raspberry Pi OS, ...), from the
# unpacked agent package. Administration > Agents > Enroll agent gives a one-line command that downloads the
# package from the server, checks its SHA-256 and runs this.
#
#   sudo ./install.sh --server https://siem-agents.example.com:9443 --token dgs1_... [--name acme-log-col]
#
# Options:
#   --server URL     DG SIEM agent endpoint (first install only)
#   --token TOKEN    enrollment token (first install only)
#   --name NAME      agent name (default: hostname)
#   --binary PATH    the agent binary (default: dg-siem-agent next to this script)
# Re-running upgrades the binary and keeps the enrollment. It also sets up automatic updates
# (dg-siem-agent-update.path), after which new versions uploaded to the server install themselves.
set -euo pipefail

SERVER="" TOKEN="" NAME="$(hostname -s | tr '[:upper:]' '[:lower:]')" BINARY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
BINARY="${BINARY:-$SCRIPT_DIR/dg-siem-agent}"
[[ -f "$BINARY" ]] || { echo "agent binary not found: $BINARY (run this from the unpacked agent package)" >&2; exit 1; }
if ! CHECK="$("$BINARY" --version 2>&1)"; then
  CODE=$?
  echo "$BINARY doesn't run on this machine (exit $CODE): $CHECK" >&2
  if [[ $CODE -eq 132 ]] || grep -qi "illegal instruction" <<<"$CHECK"; then
    echo "The CPU lacks x86-64-v2 features (SSE4.2/POPCNT). On a Proxmox VM, set Hardware > Processors > Type to x86-64-v2-AES or host, then power it off and on." >&2
  elif [[ $CODE -eq 126 ]]; then
    echo "It can't be executed here: is $(dirname "$BINARY") on a noexec mount (often /tmp)? Unpack the package somewhere else." >&2
  fi
  exit 1
fi

DATA=/var/lib/dg-siem-agent
ETC=/etc/dg-siem-agent

id dg-siem-agent >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin dg-siem-agent
# File inputs: /var/log is usually readable by the adm group on Debian/Ubuntu (and RHEL).
if getent group adm >/dev/null 2>&1; then usermod -aG adm dg-siem-agent; fi
install -d -o dg-siem-agent -g dg-siem-agent -m 0700 "$DATA"
install -d -m 0755 "$ETC"

# Replace via a temporary name and rename, so a running agent keeps its (old) file until it restarts.
install -m 0755 "$BINARY" /usr/local/bin/dg-siem-agent.new
mv -f /usr/local/bin/dg-siem-agent.new /usr/local/bin/dg-siem-agent
echo "Installed dg-siem-agent $(/usr/local/bin/dg-siem-agent --version)"

[[ -f "$ETC/appsettings.json" ]] || cat > "$ETC/appsettings.json" <<JSON
{
  "Agent": {
    "DataDirectory": "$DATA"
  }
}
JSON

for unit in dg-siem-agent.service dg-siem-agent-update.service dg-siem-agent-update.path; do
  if [[ -f "$SCRIPT_DIR/$unit" ]]; then
    install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
  else
    echo "warning: $unit isn't in the package; skipping it" >&2
  fi
done
systemctl daemon-reload

if [[ ! -f "$DATA/state.txt" ]]; then
  [[ -n "$SERVER" && -n "$TOKEN" ]] || { echo "first install needs --server and --token" >&2; exit 2; }
  runuser -u dg-siem-agent -- /usr/local/bin/dg-siem-agent enroll --server "$SERVER" --token "$TOKEN" --name "$NAME" --data-dir "$DATA"
fi

# Automatic updates: the agent asks, root installs (see dg-siem-agent-update.service).
# A failure here (e.g. the machine is out of inotify watches) shouldn't stop the agent itself being restarted.
if [[ -f /etc/systemd/system/dg-siem-agent-update.path ]]; then
  systemctl reset-failed dg-siem-agent-update.path 2>/dev/null || true
  if ! systemctl enable --now dg-siem-agent-update.path; then
    echo "warning: automatic updates aren't active: dg-siem-agent-update.path didn't start (see journalctl -xe)." >&2
    echo "         If it says 'inotify watch limit reached', raise fs.inotify.max_user_instances / max_user_watches, then: systemctl enable --now dg-siem-agent-update.path" >&2
  fi
fi
systemctl enable dg-siem-agent
systemctl restart dg-siem-agent
echo "dg-siem-agent is running. Logs: journalctl -u dg-siem-agent -f   Updates: journalctl -u dg-siem-agent-update"
