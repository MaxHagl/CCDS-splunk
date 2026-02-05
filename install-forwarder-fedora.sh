#!/usr/bin/env bash
set -Eeuo pipefail

# --- CONFIGURATION ---
SPLUNK_SERVER_IP="${SPLUNK_SERVER_IP:-172.20.242.20}"
SPLUNK_RECEIVE_PORT="${SPLUNK_RECEIVE_PORT:-9997}"
DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/10.2.0/linux/splunkforwarder-10.2.0-d749cb17ea65-linux-amd64.tgz"
INSTALL_DIR="/opt"
SPLUNK_HOME="$INSTALL_DIR/splunkforwarder"
SPLUNK_OS_USER="splunk"

# --- Credentials ---
read -r -p "Enter Splunk UF admin username [admin]: " UF_ADMIN
UF_ADMIN="${UF_ADMIN:-admin}"
read -r -s -p "Enter Splunk UF admin password: " UF_PASS
echo ""

# --- 1. Dependencies & User Setup ---
echo "[*] Preparing environment..."
sudo dnf install -y tar policycoreutils-python-utils libcap-devel >/dev/null

if ! id "$SPLUNK_OS_USER" >/dev/null 2>&1; then
    sudo useradd -r -m -d "$SPLUNK_HOME" -s /sbin/nologin "$SPLUNK_OS_USER"
fi

# --- 2. Download & Extraction ---
echo "[*] Downloading and extracting Splunk..."
curl -L -o /tmp/splunkforwarder.tgz "$DOWNLOAD_URL"
sudo tar -xzf /tmp/splunkforwarder.tgz -C "$INSTALL_DIR"
sudo chown -R "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME"

# --- 3. Security: Linux Capabilities ---
# This allows the 'splunk' user to read system logs without root privileges
echo "[*] Granting DAC_READ_SEARCH capabilities..."
sudo setcap 'cap_dac_read_search+ep' "$SPLUNK_HOME/bin/splunk"

# --- 4. Seed Credentials ---
sudo mkdir -p "$SPLUNK_HOME/etc/system/local"
sudo tee "$SPLUNK_HOME/etc/system/local/user-seed.conf" >/dev/null <<EOF
[user_info]
USERNAME = $UF_ADMIN
PASSWORD = $UF_PASS
EOF
sudo chown "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME/etc/system/local/user-seed.conf"

# --- 5. Boot-Start Fix (The Screenshot Error) ---
echo "[*] Initializing and setting up systemd..."
# Start once as the splunk user to generate internal certs/configs
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" stop

# CRITICAL: Run as root to create the systemd unit file
sudo "$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_OS_USER" --accept-license --answer-yes --no-prompt

# --- 6. Start Service & Configure Forwarding ---
sudo systemctl daemon-reload
sudo systemctl enable SplunkForwarder
sudo systemctl start SplunkForwarder

# Mask credentials using an environment variable
export SPLUNK_AUTH="$UF_ADMIN:$UF_PASS"

echo "[*] Configuring forward-server and monitors..."
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add forward-server "${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}" -auth "$SPLUNK_AUTH"

# Monitor Fedora-specific system logs
[[ -f /var/log/secure ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/secure -sourcetype linux_secure -auth "$SPLUNK_AUTH"
[[ -f /var/log/messages ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/messages -sourcetype syslog -auth "$SPLUNK_AUTH"

# --- 7. Final Verification ---
unset SPLUNK_AUTH
rm -f /tmp/splunkforwarder.tgz

echo "--------------------------------------------------"
echo "Installation complete."
echo "Service Status: $(systemctl is-active SplunkForwarder)"
echo "--------------------------------------------------"


sudo systemctl daemon-reload
sudo systemctl enable SplunkForwarder
sudo systemctl start SplunkForwarder
sudo systemctl status SplunkForwarder
