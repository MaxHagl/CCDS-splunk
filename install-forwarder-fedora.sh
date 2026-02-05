#!/usr/bin/env bash
set -Eeuo pipefail

# ===========================
# Splunk Universal Forwarder Installer (Fedora Hardened)
# - Runs as dedicated 'splunk' user
# - Uses Linux Capabilities (cap_dac_read_search) to read logs
# - Properly handles systemd boot-start on Fedora
# ===========================

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

# --- 1. Prerequisites ---
echo "[*] Installing Fedora dependencies..."
sudo dnf install -y tar policycoreutils-python-utils libcap-devel >/dev/null

# --- 2. Download & Extraction ---
echo "[*] Downloading Splunk UF..."
curl -L -o /tmp/splunkforwarder.tgz "$DOWNLOAD_URL"

if ! id "$SPLUNK_OS_USER" >/dev/null 2>&1; then
    echo "[*] Creating OS user '$SPLUNK_OS_USER'..."
    sudo useradd -r -m -d "$SPLUNK_HOME" -s /sbin/nologin "$SPLUNK_OS_USER"
fi

echo "[*] Extracting to $INSTALL_DIR..."
sudo tar -xzf /tmp/splunkforwarder.tgz -C "$INSTALL_DIR"
sudo chown -R "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME"

# --- 3. Security Hardening (Capabilities & SELinux) ---
echo "[*] Applying security hardening..."
# Allow the splunk binary to read logs without being root
sudo setcap 'cap_dac_read_search+ep' "$SPLUNK_HOME/bin/splunk"

# Set SELinux contexts so the service can manage its own logs
sudo semanage fcontext -a -t var_log_t "$SPLUNK_HOME/var/log/splunk(/.*)?" || true
sudo restorecon -Rv "$SPLUNK_HOME" >/dev/null

# --- 4. Seed Credentials ---
echo "[*] Seeding admin credentials..."
sudo mkdir -p "$SPLUNK_HOME/etc/system/local"
sudo tee "$SPLUNK_HOME/etc/system/local/user-seed.conf" >/dev/null <<EOF
[user_info]
USERNAME = $UF_ADMIN
PASSWORD = $UF_PASS
EOF
sudo chown "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME/etc/system/local/user-seed.conf"
sudo chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"

# --- 5. Initial Start & Systemd Setup ---
echo "[*] Initializing Splunk..."
# Start once as the splunk user to trigger initialization
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt
# Stop it so we can hand control to systemd
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" stop

echo "[*] Configuring systemd boot-start..."
# RUN AS ROOT: This creates the unit file in /etc/systemd/system/
sudo "$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_OS_USER" --accept-license --answer-yes --no-prompt

# --- 6. Configure Forwarding & Monitors ---
echo "[*] Starting service and configuring outputs..."
sudo systemctl daemon-reload
sudo systemctl enable SplunkForwarder
sudo systemctl start SplunkForwarder

# Use Env Vars to hide credentials from 'ps' output
export SPLUNK_AUTHENTICATE="$UF_ADMIN:$UF_PASS"

# Configure Receiver
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add forward-server "${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}" -auth "$SPLUNK_AUTHENTICATE"

# Add standard Fedora log monitors
echo "[*] Adding Fedora log monitors (/var/log/secure, /var/log/messages)..."
[[ -f /var/log/secure ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/secure -sourcetype linux_secure -auth "$SPLUNK_AUTHENTICATE"
[[ -f /var/log/messages ]] && sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor /var/log/messages -sourcetype syslog -auth "$SPLUNK_AUTHENTICATE"

# --- 7. Cleanup & Verification ---
unset UF_PASS
unset SPLUNK_AUTHENTICATE
rm -f /tmp/splunkforwarder.tgz

echo ""
echo "[+] DONE!"
echo "--------------------------------------------------"
echo "Service Status: $(systemctl is-active SplunkForwarder)"
echo "Boot Status:    $(systemctl is-enabled SplunkForwarder)"
echo "Running User:   $(ps -ef | grep [s]plunkd | awk '{print $1}' | head -n 1)"
echo "--------------------------------------------------"
