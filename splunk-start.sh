#!/usr/bin/env bash
set -Eeuo pipefail

# --- CONFIGURATION ---
SPLUNK_SERVER="172.20.242.20"
SPLUNK_PORT="9997"
SPLUNK_USER="splunk"
INSTALL_DIR="/opt/splunkforwarder"
# Verified Linux 64-bit Link
DL_URL="https://download.splunk.com/products/universalforwarder/releases/10.0.3/linux/splunkforwarder-10.0.3-adbac1c8811c-linux-amd64.tgz"

# --- CREDENTIALS ---
read -r -p "Enter NEW Splunk Admin Username [admin]: " UF_ADMIN
UF_ADMIN="${UF_ADMIN:-admin}"
read -r -s -p "Enter NEW Splunk Admin Password: " UF_PASS
echo ""

# ==============================================================================
# PHASE 1: THE PURGE (Factory Reset)
# ==============================================================================
echo ""
echo "[💀] DETECTED BROKEN STATE. INITIATING FACTORY RESET..."

# 1. Stop service if running (ignore errors)
systemctl stop SplunkForwarder 2>/dev/null || true
/opt/splunkforwarder/bin/splunk stop 2>/dev/null || true
killall -9 splunkd 2>/dev/null || true

# 2. Disable and remove systemd unit
systemctl disable SplunkForwarder 2>/dev/null || true
rm -f /etc/systemd/system/SplunkForwarder.service
rm -f /etc/init.d/splunk
systemctl daemon-reload

# 3. Nuke installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo "[*] Wiping installation directory: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
fi

# 4. Remove user to clear old UIDs
if id "$SPLUNK_USER" >/dev/null 2>&1; then
    echo "[*] Removing old splunk user..."
    userdel -f "$SPLUNK_USER" 2>/dev/null || true
    # Remove group if it remains
    groupdel "$SPLUNK_USER" 2>/dev/null || true
fi

echo "[✅] System is clean."
sleep 2

# ==============================================================================
# PHASE 2: THE FRESH INSTALL
# ==============================================================================
echo ""
echo "[🌱] STARTING FRESH INSTALL..."

# 1. Re-create User
useradd -r -m -d "$INSTALL_DIR" -s /sbin/nologin "$SPLUNK_USER"

# 2. Download
if [ ! -f "/tmp/splunk.tgz" ]; then
    echo "[*] Downloading Splunk..."
    curl -L -o /tmp/splunk.tgz "$DL_URL"
fi

# 3. Extract
echo "[*] Extracting..."
tar -xzf /tmp/splunk.tgz -C /opt

# 4. Create Directory Structure Manually (Fixes 'No such file' error)
echo "[*] Enforcing directory structure and ownership..."
mkdir -p "$INSTALL_DIR/var/log/splunk"
mkdir -p "$INSTALL_DIR/var/run/splunk"
mkdir -p "$INSTALL_DIR/etc/system/local"

# 5. Pre-Seed Credentials (Fixes 'Remote Login Disabled')
echo "[*] Seeding credentials..."
cat > "$INSTALL_DIR/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = $UF_ADMIN
PASSWORD = $UF_PASS
EOF

# 6. Set Capabilities (Fixes 'Permission Denied' on logs)
# Install libcap if missing
if command -v apt-get &>/dev/null; then apt-get install -y libcap2-bin >/dev/null; fi
if command -v dnf &>/dev/null; then dnf install -y libcap-devel >/dev/null; fi
setcap 'cap_dac_read_search+ep' "$INSTALL_DIR/bin/splunk"

# 7. Apply Ownership (Recursive)
chown -R "$SPLUNK_USER:$SPLUNK_USER" "$INSTALL_DIR"

# ==============================================================================
# PHASE 3: BOOTSTRAP & CONNECT
# ==============================================================================
echo "[🚀] BOOTSTRAPPING..."

# 1. Generate Systemd Unit (As Root, running as Splunk User)
# We do NOT start it yet. We just generate the config.
"$INSTALL_DIR/bin/splunk" enable boot-start -user "$SPLUNK_USER" --accept-license --answer-yes --no-prompt

# 2. Start Service via Systemd
systemctl daemon-reload
systemctl enable SplunkForwarder
systemctl start SplunkForwarder

# 3. Wait for startup (Critical!)
echo "[⏳] Waiting 10s for service to stabilize..."
sleep 10

# 4. Configure Forwarding
echo "[🔗] Connecting to Indexer..."
export SPLUNK_AUTH="$UF_ADMIN:$UF_PASS"
sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" add forward-server "${SPLUNK_SERVER}:${SPLUNK_PORT}" -auth "$SPLUNK_AUTH"

# 5. Add Monitors
sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" add monitor /var/log/syslog -auth "$SPLUNK_AUTH" || true
sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" add monitor /var/log/auth.log -auth "$SPLUNK_AUTH" || true
sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" add monitor /var/log/secure -auth "$SPLUNK_AUTH" || true

# ==============================================================================
# FINAL CHECK
# ==============================================================================
echo ""
echo "---------------------------------------------------"
echo "STATUS CHECK:"
sudo -u "$SPLUNK_USER" "$INSTALL_DIR/bin/splunk" list forward-server
echo "---------------------------------------------------"
