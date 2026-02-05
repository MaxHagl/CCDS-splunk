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
read -r -p "Enter UF admin username [admin]: " UF_ADMIN
UF_ADMIN="${UF_ADMIN:-admin}"
read -r -s -p "Enter UF admin password: " UF_PASS
echo ""

# --- Prerequisites ---
echo "[*] Installing dependencies..."
sudo dnf install -y tar policycoreutils-python-utils libcap-devel >/dev/null

# --- Download & Extraction ---
echo "[*] Downloading Splunk UF..."
curl -L -o /tmp/splunkforwarder.tgz "$DOWNLOAD_URL"

if ! id "$SPLUNK_OS_USER" >/dev/null 2>&1; then
    sudo useradd -r -m -d "$SPLUNK_HOME" -s /sbin/nologin "$SPLUNK_OS_USER"
fi

sudo tar -xzf /tmp/splunkforwarder.tgz -C "$INSTALL_DIR"
sudo chown -R "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME"

# --- Security: Linux Capabilities ---
# This allows the splunk user to read system logs without being root
echo "[*] Granting DAC_READ_SEARCH capabilities to Splunk binary..."
sudo setcap 'cap_dac_read_search+ep' "$SPLUNK_HOME/bin/splunk"

# --- Seed Credentials ---
sudo mkdir -p "$SPLUNK_HOME/etc/system/local"
sudo tee "$SPLUNK_HOME/etc/system/local/user-seed.conf" >/dev/null <<EOF
[user_info]
USERNAME = $UF_ADMIN
PASSWORD = $UF_PASS
EOF
sudo chown "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME/etc/system/local/user-seed.conf"
sudo chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"

# --- Initialize & Boot Start ---
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt
sudo "$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_OS_USER" --accept-license --answer-yes --no-prompt

# --- SELinux Policy ---
echo "[*] Setting SELinux contexts for Fedora..."
sudo semanage fcontext -a -t var_log_t "$SPLUNK_HOME/var/log/splunk(/.*)?" || true
sudo restorecon -Rv "$SPLUNK_HOME" >/dev/null

# --- Networking & Monitors ---
export SPLUNK_AUTHENTICATE="$UF_ADMIN:$UF_PASS"
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add forward-server "${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}" -auth "$SPLUNK_AUTHENTICATE"

# Monitor Fedora-specific log paths
[[ -f /var/log/secure ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/secure -sourcetype linux_secure -auth "$SPLUNK_AUTHENTICATE"
[[ -f /var/log/messages ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/messages -sourcetype syslog -auth "$SPLUNK_AUTHENTICATE"

# Cleanup
unset UF_PASS
unset SPLUNK_AUTHENTICATE
rm -f /tmp/splunkforwarder.tgz

echo "[+] Done. Splunk UF is running as '$SPLUNK_OS_USER' with restricted capabilities."
