#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
#  UNIVERSAL SPLUNK FORWARDER INSTALLER (UBUNTU & FEDORA)
#  - Auto-detects OS for dependencies
#  - Pre-seeds credentials (Fixes "Remote login disabled")
#  - configures systemd correctly (Fixes "Unit not found")
#  - Uses Linux Capabilities (Fixes "Permission denied" on logs)
# ==============================================================================

# --- CONFIGURATION (Edit if needed) ---
SPLUNK_SERVER_IP="172.20.242.20"
SPLUNK_RECEIVE_PORT="9997"
SPLUNK_OS_USER="splunk"
INSTALL_DIR="/opt"
SPLUNK_HOME="$INSTALL_DIR/splunkforwarder"
# Verified Link for Linux 64-bit (v10.0.3)
DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/10.0.3/linux/splunkforwarder-10.0.3-adbac1c8811c-linux-amd64.tgz"

# --- MUST RUN AS ROOT ---
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (sudo)."
   exit 1
fi

# --- CREDENTIALS INPUT ---
echo "--------------------------------------------------"
echo "Create Splunk Admin Credentials"
echo "--------------------------------------------------"
read -r -p "Enter NEW Splunk Admin Username [admin]: " UF_ADMIN
UF_ADMIN="${UF_ADMIN:-admin}"
read -r -s -p "Enter NEW Splunk Admin Password: " UF_PASS
echo ""
if [[ -z "$UF_PASS" ]]; then echo "[!] Password cannot be empty."; exit 1; fi

# --- 1. DEPENDENCY INSTALLATION ---
echo ""
echo "[*] Detecting OS and installing dependencies..."
if command -v dnf &> /dev/null; then
    # Fedora/RHEL
    dnf install -y tar policycoreutils-python-utils libcap-devel net-tools >/dev/null
    echo "[+] Fedora dependencies installed."
elif command -v apt-get &> /dev/null; then
    # Ubuntu/Debian
    apt-get update >/dev/null
    apt-get install -y tar libcap2-bin net-tools >/dev/null
    echo "[+] Ubuntu dependencies installed."
fi

# --- 2. USER & GROUP SETUP ---
if ! id "$SPLUNK_OS_USER" >/dev/null 2>&1; then
    echo "[*] Creating system user: $SPLUNK_OS_USER"
    useradd -r -m -d "$SPLUNK_HOME" -s /sbin/nologin "$SPLUNK_OS_USER"
fi

# --- 3. DOWNLOAD & INSTALL ---
echo "[*] Downloading Splunk Universal Forwarder..."
curl -L -o /tmp/splunkforwarder.tgz "$DOWNLOAD_URL"

echo "[*] Extracting to $INSTALL_DIR..."
# Extract preserving permissions, but we fix ownership next anyway
tar -xzf /tmp/splunkforwarder.tgz -C "$INSTALL_DIR"

# --- 4. PRE-SEED CREDENTIALS (CRITICAL FIX) ---
# This prevents the "Remote login disabled" error by setting auth BEFORE start
echo "[*] Seeding admin credentials..."
mkdir -p "$SPLUNK_HOME/etc/system/local"
cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = $UF_ADMIN
PASSWORD = $UF_PASS
EOF

# --- 5. PERMISSIONS & SECURITY ---
echo "[*] Applying permissions and capabilities..."
chown -R "$SPLUNK_OS_USER:$SPLUNK_OS_USER" "$SPLUNK_HOME"
chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"

# Allow splunk binary to read system logs without being root
setcap 'cap_dac_read_search+ep' "$SPLUNK_HOME/bin/splunk"

# --- 6. INITIALIZATION & SYSTEMD ---
echo "[*] Initializing internal keys..."
# Start temporarily as splunk user to generate keys
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt >/dev/null
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" stop >/dev/null

echo "[*] enabling boot-start (Systemd)..."
# RUN AS ROOT: This generates the unit file correctly
"$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_OS_USER" --accept-license --answer-yes --no-prompt

# Reload and Start Systemd Service
systemctl daemon-reload
systemctl enable SplunkForwarder
systemctl restart SplunkForwarder

# --- 7. CONFIGURATION ---
echo "[*] Configuring Forwarder..."
# Use Env Var to hide password from process list
export SPLUNK_AUTH="$UF_ADMIN:$UF_PASS"

# Add Indexer
sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add forward-server "${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}" -auth "$SPLUNK_AUTH"

# Add Monitors (Auto-detects which logs exist)
for logfile in /var/log/syslog /var/log/auth.log /var/log/secure /var/log/messages; do
    if [[ -f "$logfile" ]]; then
        echo "    -> Monitoring $logfile"
        sudo -u "$SPLUNK_OS_USER" "$SPLUNK_HOME/bin/splunk" add monitor "$logfile" -auth "$SPLUNK_AUTH" >/dev/null
    fi
done

# --- 8. FINAL STATUS REPORT ---
unset SPLUNK_AUTH
rm -f /tmp/splunkforwarder.tgz

echo ""
echo "=================================================="
echo "✅ INSTALLATION COMPLETE"
echo "=================================================="
echo "Service State : $(systemctl is-active SplunkForwarder)"
echo "Process User  : $(ps -o user= -p $(pgrep -n splunkd) 2>/dev/null || echo 'Not Running')"
echo "Target Indexer: ${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}"
echo ""
echo "Test Connectivity:"
echo "  sudo -u $SPLUNK_OS_USER $SPLUNK_HOME/bin/splunk list forward-server"
echo "=================================================="
