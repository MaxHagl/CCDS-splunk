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

# If SELinux is Enforcing and blocks UF from reading /var/log/*, set this to 1
# (Only do this if allowed by ROE)
SET_SELINUX_PERMISSIVE="${SET_SELINUX_PERMISSIVE:-0}"

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
  if have apt-get; then
    apt-get update -y >/dev/null
    apt-get install -y curl tar netcat-openbsd libcap2-bin >/dev/null
  elif have dnf; then
    dnf -y install curl tar nc libcap rsyslog >/dev/null || dnf -y install curl tar nmap-ncat libcap rsyslog >/dev/null
    dnf -y install policycoreutils >/dev/null 2>&1 || true
  elif have yum; then
    yum -y install curl tar nc libcap rsyslog >/dev/null
    yum -y install policycoreutils >/dev/null 2>&1 || true
  else
    log "[!] No supported package manager found. Ensure curl, tar, nc, setcap exist."
  fi
}

detect_splunk_unit() {
  local unit=""
  unit="$(systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -Ei '^splunk.*(forwarder|universal).*\.service$' | head -n1 || true)"
  if [[ -z "$unit" ]]; then
    unit="$(systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -E '^SplunkForwarder\.service$' | head -n1 || true)"
  fi
  echo "$unit"
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

  if id "$SPLUNK_USER" >/dev/null 2>&1; then
    log "[*] Removing user $SPLUNK_USER"
    userdel -r -f "$SPLUNK_USER" 2>/dev/null || true
  fi
  getent group "$SPLUNK_USER" >/dev/null 2>&1 && groupdel "$SPLUNK_USER" 2>/dev/null || true

  log "[✅] Purge complete."
}

create_user() {
  log "[*] Creating service user $SPLUNK_USER"
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

  export UF_ADMIN UF_PASS
}

write_outputs_inputs() {
  log "[*] Writing outputs.conf (minimal + valid)..."
  cat > "$INSTALL_DIR/etc/system/local/outputs.conf" <<EOF
[tcpout]
defaultGroup = primary_indexer

[tcpout:primary_indexer]
server = ${SPLUNK_SERVER}:${SPLUNK_PORT}
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

configure_log_access() {
  log "[*] Ensuring Splunk user can read system logs (/var/log/*)..."

  # Ensure rsyslog is running so /var/log/messages exists on Fedora
  if systemctl list-unit-files 2>/dev/null | grep -qi '^rsyslog\.service'; then
    systemctl enable --now rsyslog >/dev/null 2>&1 || true
  fi

  # Create dedicated group and add splunk user
  groupadd -f splunklog
  usermod -aG splunklog "$SPLUNK_USER" || true
  usermod -aG systemd-journal "$SPLUNK_USER" 2>/dev/null || true

  # Give group read access (not world-readable)
  # Only change if files exist; keep scope minimal.
  for f in /var/log/messages /var/log/secure /var/log/audit/audit.log /var/log/syslog /var/log/auth.log; do
    if [[ -e "$f" ]]; then
      chgrp splunklog "$f" 2>/dev/null || true
      chmod 640 "$f" 2>/dev/null || true
    fi
  done

  # Make sure directories are searchable so splunk can traverse paths
  chmod o+x /var/log 2>/dev/null || true
  chmod o+x /var/log/audit 2>/dev/null || true

  # SELinux handling (detect + optional permissive)
  if have getenforce; then
    local mode
    mode="$(getenforce || true)"
    if [[ "$mode" == "Enforcing" ]]; then
      if [[ "$SET_SELINUX_PERMISSIVE" == "1" ]]; then
        log "[!] SELinux is Enforcing; switching to Permissive (SET_SELINUX_PERMISSIVE=1)."
        setenforce 0 || true
      else
        log "[!] SELinux is Enforcing. If Splunk still shows cannot_open, either set SET_SELINUX_PERMISSIVE=1 (if allowed) or add a proper SELinux policy."
      fi
    fi
  fi
}

fix_permissions_caps() {
  log "[*] Setting ownership and capabilities..."

  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$INSTALL_DIR"

  if ! have setcap; then
    log "[!] setcap not found; installing deps..."
    pkg_install
  fi

  if [[ -x "$INSTALL_DIR/bin/splunkd" ]]; then
    setcap 'cap_dac_read_search+ep' "$INSTALL_DIR/bin/splunkd" || true
  fi
}

start_and_enable() {
  log "[🚀] Starting Splunk UF (first start consumes user-seed.conf)..."
  sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" start --accept-license --answer-yes --no-prompt

  log "[*] Stopping UF before creating systemd unit (required by Splunk)..."
  sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" stop || true

  log "[*] Enabling boot-start (systemd) as root..."
  # MUST be run as root to write unit files, and Splunk MUST be stopped.
  "$INSTALL_DIR/bin/splunk" enable boot-start -user "$SPLUNK_USER" --accept-license --answer-yes --no-prompt || true

  systemctl daemon-reload || true

  # Now start using the unit if it exists, otherwise start via CLI
  local unit
  unit="$(detect_splunk_unit)"
  if [[ -n "$unit" ]]; then
    log "[*] Detected systemd unit: $unit"
    systemctl enable "$unit" 2>/dev/null || true
    systemctl restart "$unit" 2>/dev/null || true
  else
    log "[!] No systemd unit detected; starting via CLI instead."
    sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" start --answer-yes --no-prompt || true
  fi
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
  log "Forward-server (CLI):"
  sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" list forward-server || true
  echo ""
  log "Monitors (CLI):"
  sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" list monitor | tail -n 30 || true
  echo ""
  log "Recent UF WARN/ERROR (splunkd.log):"
  tail -n 80 "$INSTALL_DIR/var/log/splunk/splunkd.log" | egrep -i 'WARN|ERROR|cannot_open|Permission denied' || true
  log "---------------------------------------------------"
  log "Optional smoke test: run -> logger -t CCDC_TEST \"smoke $(date -Is)\""
}

main() {
  need_root
  pkg_install
  purge_install
  create_user
  download_extract
  seed_creds
  write_outputs_inputs
  configure_log_access
  fix_permissions_caps
  start_and_enable
  wait_for_splunkd
  connectivity_check
  final_status
}

main "$@"
