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
read -r -p "Enter NEW Splunk Forwarder local admin username [admin]: " UF_ADMIN
UF_ADMIN="${UF_ADMIN:-admin}"
read -r -s -p "Enter NEW Splunk Forwarder local admin password: " UF_PASS
echo ""

if [[ -z "${UF_PASS}" ]]; then
  echo "[!] UF admin password cannot be empty."
  exit 1
fi

# --- 1. Dependencies & User Setup ---
echo "[*] Preparing environment..."
if command -v dnf &> /dev/null; then
    sudo dnf install -y tar policycoreutils-python-utils libcap-devel >/dev/null
elif command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y tar libcap2-bin >/dev/null
fi

if ! id "$SPLUNK_OS_USER" >/dev/null 2>&1; then
    sudo useradd -r -m -d "$SPLUNK_HOME" -s /sbin/nologin "$SPLUNK_OS_USER"
fi

# --- 2. Download & Extraction ---
echo "[*] Downloading and extracting Splunk..."
curl -L -o /tmp/splunkforwarder.tgz "$DOWNLOAD_URL"
sudo tar -xzf /tmp/splunkforwarder.tgz -C "$INSTALL_DIR"
sudo chown -R "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME"

# --- 3. Security: Linux Capabilities ---
# Allows reading system logs without root privileges
echo "[*] Granting DAC_READ_SEARCH capabilities..."
sudo setcap 'cap_dac_read_search+ep' "$SPLUNK_HOME/bin/splunk"

# --- 4. Seed Credentials (Must happen BEFORE first start) ---
echo "[*] Seeding admin credentials..."
sudo mkdir -p "$SPLUNK_HOME/etc/system/local"
sudo tee "$SPLUNK_HOME/etc/system/local/user-seed.conf" >/dev/null <<EOF
[user_info]
USERNAME = $UF_ADMIN
PASSWORD = $UF_PASS
EOF
sudo chown -R "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME/etc/system/local"
sudo chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"

# --- 5. Boot-Start & Systemd Setup ---
echo "[*] Initializing Splunk and systemd..."
# Start once as the splunk user to process the seed file
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" stop

# Enable boot-start as root to create the systemd unit file
sudo "$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_OS_USER" --accept-license --answer-yes --no-prompt

sudo systemctl daemon-reload
sudo systemctl enable SplunkForwarder
sudo systemctl start SplunkForwarder

# --- 6. Configure Forwarding & Monitors ---
# Using environment variables to avoid cleartext passwords in 'ps' output
export SPLUNK_AUTH="$UF_ADMIN:$UF_PASS"

echo "[*] Adding forward-server ${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT} ..."
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add forward-server "${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}" -auth "$SPLUNK_AUTH"

echo "[*] Adding basic monitors..."
# Add monitors for common log paths
for log in /var/log/secure /var/log/auth.log /var/log/messages /var/log/syslog; do
    if [[ -f "$log" ]]; then
        sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor "$log" -auth "$SPLUNK_AUTH" || true
    fi
done

# --- 7. Final Verification ---
unset SPLUNK_AUTH
rm -f /tmp/splunkforwarder.tgz

echo "--------------------------------------------------"
echo "Installation complete."
echo "Service Status: \$(systemctl is-active SplunkForwarder)"
echo "--------------------------------------------------"
