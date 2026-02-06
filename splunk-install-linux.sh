#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# CONFIGURATION
# =========================
SPLUNK_SERVER="${SPLUNK_SERVER:-172.20.242.20}"
SPLUNK_PORT="${SPLUNK_PORT:-9997}"
SPLUNK_USER="${SPLUNK_USER:-splunk}"
INSTALL_DIR="${INSTALL_DIR:-/opt/splunkforwarder}"
DL_URL="${DL_URL:-https://download.splunk.com/products/universalforwarder/releases/10.0.3/linux/splunkforwarder-10.0.3-adbac1c8811c-linux-amd64.tgz}"

TMP_TGZ="/tmp/splunkforwarder.tgz"
MGMT_PORT="8089"
SERVICE_CANDIDATES=("SplunkForwarder" "splunkforwarder" "splunk-universalforwarder")

log(){ echo -e "[$(date '+%F %T %z')] $*"; }
die(){ echo -e "ERROR: $*" >&2; exit 1; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (sudo)."
}

have() { command -v "$1" &>/dev/null; }

pkg_install() {
  # Installs minimal deps across common distros
  if have apt-get; then
    apt-get update -y >/dev/null
    apt-get install -y curl tar netcat-openbsd libcap2-bin >/dev/null
  elif have dnf; then
    dnf -y install curl tar nc libcap rsyslog >/dev/null || dnf -y install curl tar nmap-ncat libcap rsyslog >/dev/null
  elif have yum; then
    yum -y install curl tar nc libcap rsyslog >/dev/null
  else
    log "[!] No supported package manager found. Ensure curl, tar, nc, setcap exist."
  fi
}

stop_any_splunk() {
  log "[*] Stopping any existing Splunk Forwarder service/processes..."

  for svc in "${SERVICE_CANDIDATES[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
  done

  if [[ -x "$INSTALL_DIR/bin/splunk" ]]; then
    "$INSTALL_DIR/bin/splunk" stop 2>/dev/null || true
  fi

  pkill -9 splunkd 2>/dev/null || true
  pkill -9 splunk 2>/dev/null || true

  # Remove common unit file paths (best-effort)
  rm -f /etc/systemd/system/SplunkForwarder.service 2>/dev/null || true
  rm -f /etc/systemd/system/splunkforwarder.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
}

purge_install() {
  log "[💀] FACTORY RESET: removing $INSTALL_DIR and old user/service state..."

  stop_any_splunk

  if [[ -d "$INSTALL_DIR" ]]; then
    log "[*] Wiping $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
  fi

  # Remove splunk user/group if exists (optional but helpful for "stuck" permissions)
  if id "$SPLUNK_USER" >/dev/null 2>&1; then
    log "[*] Removing user $SPLUNK_USER"
    userdel -r -f "$SPLUNK_USER" 2>/dev/null || true
  fi
  getent group "$SPLUNK_USER" >/dev/null 2>&1 && groupdel "$SPLUNK_USER" 2>/dev/null || true

  log "[✅] Purge complete."
}

create_user() {
  log "[*] Creating service user $SPLUNK_USER"
  # Home should NOT be /opt/splunkforwarder (avoid conflicts with extraction)
  useradd -r -m -d "/home/$SPLUNK_USER" -s /sbin/nologin "$SPLUNK_USER"
}

download_extract() {
  log "[*] Downloading UF tarball..."
  curl -fsSL -o "$TMP_TGZ" "$DL_URL"

  log "[*] Extracting to /opt..."
  tar -xzf "$TMP_TGZ" -C /opt

  [[ -d "$INSTALL_DIR" ]] || die "Expected $INSTALL_DIR after extraction, but it doesn't exist."
}

seed_creds() {
  log "[*] Seeding UF admin credentials (local management only)..."
  read -r -p "Enter NEW Splunk UF Admin Username [admin]: " UF_ADMIN
  UF_ADMIN="${UF_ADMIN:-admin}"
  read -r -s -p "Enter NEW Splunk UF Admin Password: " UF_PASS
  echo ""

  mkdir -p "$INSTALL_DIR/etc/system/local"
  cat > "$INSTALL_DIR/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = $UF_ADMIN
PASSWORD = $UF_PASS
EOF

  # Export for later use (validation only)
  export UF_ADMIN UF_PASS
}

write_outputs_inputs() {
  log "[*] Writing outputs.conf (this guarantees a forward server is configured)..."

  cat > "$INSTALL_DIR/etc/system/local/outputs.conf" <<EOF
[tcpout]
defaultGroup = primary_indexer

[tcpout:primary_indexer]
server = ${SPLUNK_SERVER}:${SPLUNK_PORT}
autoLB = false
EOF

  log "[*] Writing inputs.conf monitors (Ubuntu + Fedora/RHEL + audit)..."
  cat > "$INSTALL_DIR/etc/system/local/inputs.conf" <<'EOF'
# --- Ubuntu/Debian ---
[monitor:///var/log/syslog]
disabled = false
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
disabled = false
index = main
sourcetype = linux_secure

# --- Fedora/RHEL ---
[monitor:///var/log/messages]
disabled = false
index = main
sourcetype = syslog

[monitor:///var/log/secure]
disabled = false
index = main
sourcetype = linux_secure

# --- Linux auditd (if present) ---
[monitor:///var/log/audit/audit.log]
disabled = false
index = main
sourcetype = linux_audit
EOF
}

fix_permissions_caps() {
  log "[*] Setting ownership and capabilities..."

  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$INSTALL_DIR"

  # Ensure setcap exists
  if ! have setcap; then
    log "[!] setcap not found; installing deps..."
    pkg_install
  fi

  # Set cap on splunkd (daemon), not the CLI wrapper
  if [[ -x "$INSTALL_DIR/bin/splunkd" ]]; then
    setcap 'cap_dac_read_search+ep' "$INSTALL_DIR/bin/splunkd" || true
  fi

  # Fedora often logs auth to /var/log/secure only if rsyslog is running
  if systemctl list-unit-files | grep -qi '^rsyslog\.service'; then
    systemctl enable --now rsyslog >/dev/null 2>&1 || true
  fi
}

start_and_enable() {
  log "[🚀] Starting Splunk UF (first start consumes user-seed.conf)..."
  sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" start --accept-license --answer-yes --no-prompt

  log "[*] Enabling boot-start (systemd)..."
  "$INSTALL_DIR/bin/splunk" enable boot-start -user "$SPLUNK_USER" --accept-license --answer-yes --no-prompt

  # Start via systemd if unit exists
  systemctl daemon-reload || true
  systemctl enable SplunkForwarder 2>/dev/null || true
  systemctl restart SplunkForwarder 2>/dev/null || true
}

wait_for_splunkd() {
  log "[⏳] Waiting for splunkd mgmt port ${MGMT_PORT} to come up..."
  local i
  for i in {1..30}; do
    if ss -lnt 2>/dev/null | grep -q ":${MGMT_PORT}"; then
      log "[✅] splunkd is listening on ${MGMT_PORT}"
      return 0
    fi
    sleep 1
  done
  log "[!] splunkd mgmt port didn't appear. Checking status..."
  sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" status || true
  return 0
}

connectivity_check() {
  log "[*] Checking connectivity to ${SPLUNK_SERVER}:${SPLUNK_PORT} ..."
  if have nc; then
    nc -vz "$SPLUNK_SERVER" "$SPLUNK_PORT" || log "[!] nc failed (network/firewall/route?). UF may queue data."
  else
    log "[!] nc not available; skipping."
  fi
}

final_status() {
  log "---------------------------------------------------"
  log "STATUS CHECK:"
  sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" status || true
  echo ""
  log "FORWARD SERVER (from outputs.conf):"
  if [[ -f "$INSTALL_DIR/etc/system/local/outputs.conf" ]]; then
    sed -n '1,200p' "$INSTALL_DIR/etc/system/local/outputs.conf"
  else
    log "[!] outputs.conf missing!"
  fi
  echo ""
  log "CLI VIEW (may show empty if splunkd isn't ready, but outputs.conf is authoritative):"
  sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" list forward-server || true
  log "---------------------------------------------------"
  log "Tip: If you still see 'Could not send data to output queue', it's almost always connectivity to the indexer on 9997."
}

main() {
  need_root
  pkg_install
  purge_install
  create_user
  download_extract
  seed_creds
  write_outputs_inputs
  fix_permissions_caps
  start_and_enable
  wait_for_splunkd
  connectivity_check
  final_status
}

main "$@"
