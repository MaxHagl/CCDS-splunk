# ===========================
# Splunk Universal Forwarder Installer (Windows 11 / Server 2019)
# - Installs via MSI for proper service integration
# - Runs as 'LocalSystem' (Standard for Windows UFs)
# - Configures receiving and basic Event Log monitoring
# ===========================

# --- CONFIGURATION ---
$SPLUNK_SERVER_IP = "172.20.242.20"
$SPLUNK_RECEIVE_PORT = "9997"
$MSI_URL = "https://download.splunk.com/products/universalforwarder/releases/10.2.0/windows/splunkforwarder-10.2.0-d749cb17ea65-x64-release.msi"
$TEMP_MSI = "$env:TEMP\splunk_uf.msi"

# --- Credentials (For Splunk Local Admin) ---
$UF_ADMIN = Read-Host -Prompt "Enter NEW Splunk Forwarder local admin username [admin]"
if ([string]::IsNullOrWhiteSpace($UF_ADMIN)) { $UF_ADMIN = "admin" }
$UF_PASS = Read-Host -Prompt "Enter NEW Splunk Forwarder local admin password" -AsSecureString
# Convert secure string to plain text for the installer argument
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UF_PASS)
$PLAIN_PASS = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# --- 1. Download MSI ---
Write-Host "[*] Downloading Splunk Universal Forwarder MSI..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $MSI_URL -OutFile $TEMP_MSI

# --- 2. Silent Installation ---
# Note: AGREETOLICENSE=Yes is required for silent install.
Write-Host "[*] Installing Splunk Forwarder..." -ForegroundColor Cyan
$MSIArgs = @(
    "/i", "`"$TEMP_MSI`"",
    "/quiet",
    "AGREETOLICENSE=Yes",
    "RECEIVING_INDEXER=`"$($SPLUNK_SERVER_IP):$($SPLUNK_RECEIVE_PORT)`"",
    "LAUNCHSPLUNK=1",
    "SPLUNKPASSWORD=`"$PLAIN_PASS`""
)

Start-Process msiexec.exe -ArgumentList $MSIArgs -Wait

# --- 3. Post-Install Configuration (CLI) ---
$SPLUNK_BIN = "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe"

# Wait a moment for the service to initialize
Start-Sleep -Seconds 5

Write-Host "[*] Configuring standard Windows Event Log monitors..." -ForegroundColor Cyan
& $SPLUNK_BIN add eventlog System -auth "$($UF_ADMIN):$($PLAIN_PASS)"
& $SPLUNK_BIN add eventlog Security -auth "$($UF_ADMIN):$($PLAIN_PASS)"
& $SPLUNK_BIN add eventlog Application -auth "$($UF_ADMIN):$($PLAIN_PASS)"

# --- 4. Verification ---
Write-Host "`n--------------------------------------------------" -ForegroundColor Yellow
Write-Host "Installation Complete."
Write-Host "Service Status: $(Get-Service -Name SplunkForwarder | Select-Object -ExpandProperty Status)"
Write-Host "Forwarding to:  $($SPLUNK_SERVER_IP):$($SPLUNK_RECEIVE_PORT)"
Write-Host "--------------------------------------------------" -ForegroundColor Yellow

# Cleanup
Remove-Item $TEMP_MSI -ErrorAction SilentlyContinue
