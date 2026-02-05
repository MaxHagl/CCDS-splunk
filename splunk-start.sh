#!/usr/bin/env bash
set -Eeuo pipefail

# ===========================
# Splunk Universal Forwarder Installer (TGZ) - FIXED
# - Creates local UF admin user (avoids "remote login disabled"/"no users exist")
# - Runs UF as dedicated OS user "splunk"
# - Adds forward-server + basic monitors
# ===========================

# --- CONFIGURATION ---
SPLUNK_SERVER_IP="${SPLUNK_SERVER_IP:-172.20.242.20}"   # Splunk Enterprise receiver (indexer/HF) IP
SPLUNK_RECEIVE_PORT="${SPLUNK_RECEIVE_PORT:-9997}"      # Splunk receiving port (default 9997)
DOWNLOAD_URL="${DOWNLOAD_URL:-https://download.splunk.com/products/universalforwarder/releases/10.2.0/linux/splunkforwarder-10.2.0-d749cb17ea65-linux-amd64.tgz}"
INSTALL_DIR="${INSTALL_DIR:-/opt}"
SPLUNK_HOME="${SPLUNK_HOME:-$INSTALL_DIR/splunkforwarder}"

# --- OS USER (UF should not run as root long-term) ---
SPLUNK_OS_USER="${SPLUNK_OS_USER:-splunk}"

# --- What to collect (tweak as needed) ---
MONITOR_AUTH_LOG="${MONITOR_AUTH_LOG:-true}"
MONITOR_SYSLOG="${MONITOR_SYSLOG:-true}"
MONITOR_NGINX="${MONITOR_NGINX:-false}"
MONITOR_APACHE="${MONITOR_APACHE:-false}"

# --- Prompt for UF LOCAL admin creds (this fixes the issue) ---
read -r -p "Enter NEW Splunk Forwarder local admin username [admin]: " UF_ADMIN
UF_ADMIN="${UF_ADMIN:-admin}"
read -r -s -p "Enter NEW Splunk Forwarder local admin password: " UF_PASS
echo ""
if [[ -z "${UF_PASS}" ]]; then
  echo "[!] UF admin password cannot be empty."
  exit 1
fi

# --- Optional: prompt for Splunk Enterprise admin creds (NOT required for UF->indexer forwarding) ---
# The forwarder does NOT need Splunk Enterprise admin creds to forward.
# Leaving this off avoids confusion and storing Enterprise credentials on endpoints.

echo "[*] Checking connectivity to Splunk receiver ${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT} ..."
# nc might not be installed everywhere; try bash TCP check first
timeout 3 bash -c "cat < /dev/null > /dev/tcp/${SPLUNK_SERVER_IP}/${SPLUNK_RECEIVE_PORT}" 2>/dev/null \
  && echo "[+] TCP ${SPLUNK_RECEIVE_PORT} reachable" \
  || echo "[!] WARNING: Cannot confirm TCP ${SPLUNK_RECEIVE_PORT} reachability (may still work)."

cd /tmp

echo "[*] Downloading Splunk Universal Forwarder..."
curl -L -o splunkforwarder.tgz "$DOWNLOAD_URL" >/dev/null 2>&1 || wget -O splunkforwarder.tgz "$DOWNLOAD_URL"

echo "[*] Extracting Splunk Forwarder to $INSTALL_DIR..."
sudo tar -xzf splunkforwarder.tgz -C "$INSTALL_DIR"

# Ensure OS user exists
if ! id "$SPLUNK_OS_USER" >/dev/null 2>&1; then
  echo "[*] Creating OS user '$SPLUNK_OS_USER'..."
  sudo useradd -r -m -d "$SPLUNK_HOME" -s /bin/bash "$SPLUNK_OS_USER"
fi

echo "[*] Fixing ownership/permissions under $SPLUNK_HOME..."
sudo chown -R "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME"
sudo chmod -R u+rwX,g+rX "$SPLUNK_HOME"
sudo chmod -R o-rwx "$SPLUNK_HOME"

# Seed local admin creds for first start (one-time)
echo "[*] Seeding Splunk Forwarder local admin via user-seed.conf (one-time)..."
sudo mkdir -p "$SPLUNK_HOME/etc/system/local"
sudo tee "$SPLUNK_HOME/etc/system/local/user-seed.conf" >/dev/null <<EOF
[user_info]
USERNAME = $UF_ADMIN
PASSWORD = $UF_PASS
EOF
sudo chown "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME/etc/system/local/user-seed.conf"
sudo chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"

echo "[*] Starting UF (accept license)..."
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt

# Remove seed so password isn't left on disk
echo "[*] Removing user-seed.conf after initialization..."
sudo rm -f "$SPLUNK_HOME/etc/system/local/user-seed.conf"

echo "[*] Enabling boot-start (systemd) as user '$SPLUNK_OS_USER'..."
sudo "$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_OS_USER" --accept-license --answer-yes --no-prompt >/dev/null

# Add forward-server (authenticate to UF locally)
echo "[*] Configuring forward-server ${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT} ..."
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add forward-server "${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}" -auth "${UF_ADMIN}:${UF_PASS}"

# Add basic monitors (safe)
echo "[*] Adding basic log monitors..."
if [[ "$MONITOR_AUTH_LOG" == "true" ]]; then
  if [[ -f /var/log/auth.log ]]; then
    sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/auth.log -sourcetype linux_secure -auth "${UF_ADMIN}:${UF_PASS}" || true
  elif [[ -f /var/log/secure ]]; then
    sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/secure -sourcetype linux_secure -auth "${UF_ADMIN}:${UF_PASS}" || true
  fi
fi

if [[ "$MONITOR_SYSLOG" == "true" ]]; then
  if [[ -f /var/log/syslog ]]; then
    sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/syslog -sourcetype syslog -auth "${UF_ADMIN}:${UF_PASS}" || true
  elif [[ -f /var/log/messages ]]; then
    sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/messages -sourcetype syslog -auth "${UF_ADMIN}:${UF_PASS}" || true
  fi
fi

if [[ "$MONITOR_NGINX" == "true" ]]; then
  [[ -f /var/log/nginx/access.log ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/nginx/access.log -sourcetype nginx:access -auth "${UF_ADMIN}:${UF_PASS}" || true
  [[ -f /var/log/nginx/error.log  ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/nginx/error.log  -sourcetype nginx:error  -auth "${UF_ADMIN}:${UF_PASS}" || true
fi

if [[ "$MONITOR_APACHE" == "true" ]]; then
  [[ -f /var/log/apache2/access.log ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/apache2/access.log -sourcetype apache:access -auth "${UF_ADMIN}:${UF_PASS}" || true
  [[ -f /var/log/apache2/error.log  ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/apache2/error.log  -sourcetype apache:error  -auth "${UF_ADMIN}:${UF_PASS}" || true
fi

echo "[*] Restarting UF..."
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" restart -auth "${UF_ADMIN}:${UF_PASS}"

echo ""
echo "[+] Done."
echo "    UF Home:     $SPLUNK_HOME"


echo "    Forwarding:  ${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}"
echo "    Service:     systemctl status SplunkForwarder"
echo "    Verify:      sudo -u $SPLUNK_OS_USER $SPLUNK_HOME/bin/splunk list forward-server -auth ${UF_ADMIN}:******"


sudo /opt/splunkforwarder/bin/splunk stop


sudo /opt/splunkforwarder/bin/splunk enable boot-start -user splunk --accept-license --answer-yes --no-prompt

sudo systemctl daemon-reload
sudo systemctl enable SplunkForwarder
sudo systemctl start SplunkForwarder

sudo systemctl status SplunkForwarder
