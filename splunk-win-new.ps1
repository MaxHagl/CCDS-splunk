# ==============================================================================
# Splunk Universal Forwarder Installer (Complete Fix)
# Tested on: Windows 11 / Server 2019
# ==============================================================================

# --- CONFIGURATION ---
$SPLUNK_SERVER_IP = "172.20.242.20"
$SPLUNK_RECEIVE_PORT = "9997"
# Verified stable link for v10.0.3 (x64)
$MSI_URL = "https://download.splunk.com/products/universalforwarder/releases/10.0.3/windows/splunkforwarder-10.0.3-adbac1c8811c-windows-x64.msi"
$TEMP_MSI = "$env:TEMP\splunk_uf.msi"

# Paths
$SPLUNK_HOME = "C:\Program Files\SplunkUniversalForwarder"
$SPLUNK_BIN = "$SPLUNK_HOME\bin\splunk.exe"
$INPUTS_CONF = "$SPLUNK_HOME\etc\system\local\inputs.conf"
$SERVER_CONF = "$SPLUNK_HOME\etc\system\local\server.conf"

# --- Credentials ---
Write-Host "`n--- Credentials Setup ---" -ForegroundColor Cyan
$UF_ADMIN = Read-Host -Prompt "Enter NEW Splunk Forwarder local admin username [admin]"
if ([string]::IsNullOrWhiteSpace($UF_ADMIN)) { $UF_ADMIN = "admin" }
$UF_PASS = Read-Host -Prompt "Enter NEW Splunk Forwarder local admin password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UF_PASS)
$PLAIN_PASS = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# --- 1. Download MSI ---
Write-Host "`n[*] Downloading Splunk Universal Forwarder MSI..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $MSI_URL -OutFile $TEMP_MSI -ErrorAction Stop
} catch {
    Write-Host "[!] Download Failed! Check internet or URL." -ForegroundColor Red
    exit
}

# --- 2. Silent Installation ---
Write-Host "[*] Installing Splunk Forwarder..." -ForegroundColor Cyan
$MSIArgs = @(
    "/i", "`"$TEMP_MSI`"",
    "/quiet",
    "AGREETOLICENSE=Yes",
    "RECEIVING_INDEXER=`"$($SPLUNK_SERVER_IP):$($SPLUNK_RECEIVE_PORT)`"",
    "LAUNCHSPLUNK=1",
    "SPLUNKPASSWORD=`"$PLAIN_PASS`"",
    "SPLUNKUSERNAME=`"$UF_ADMIN`""
)

Start-Process msiexec.exe -ArgumentList $MSIArgs -Wait

# --- 3. FIX: Create inputs.conf (Solves 'No Data' issue) ---
Write-Host "[*] Configuring inputs.conf (Enabling Windows Logs)..." -ForegroundColor Cyan

# Wait for directory to be created by installer
while (-not (Test-Path "$SPLUNK_HOME\etc\system\local")) { Start-Sleep -Seconds 2 }

$InputsContent = @"
[default]
host = $env:COMPUTERNAME

[WinEventLog://Application]
disabled = 0
index = main

[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main
"@

Set-Content -Path $INPUTS_CONF -Value $InputsContent -Force

# --- 4. FIX: Patch server.conf (Solves 'Remote Login Disabled' error) ---
Write-Host "[*] Patching server.conf to allow login..." -ForegroundColor Cyan

# Create server.conf if missing, or append if exists
if (-not (Test-Path $SERVER_CONF)) {
    Set-Content -Path $SERVER_CONF -Value "[general]`r`nallowRemoteLogin = always"
} else {
    Add-Content -Path $SERVER_CONF -Value "`r`n[general]`r`nallowRemoteLogin = always"
}

# --- 5. Restart Service ---
Write-Host "[*] Restarting Splunk Service to apply changes..." -ForegroundColor Cyan
Restart-Service -Name SplunkForwarder -Force
Start-Sleep -Seconds 10 # Give it time to initialize

# --- 6. Verification ---
Write-Host "`n==================================================" -ForegroundColor Yellow
Write-Host "             FINAL VERIFICATION"
Write-Host "==================================================" -ForegroundColor Yellow

# A. Service Status
$ServiceStatus = Get-Service -Name SplunkForwarder | Select-Object -ExpandProperty Status
Write-Host "1. Service Status:   $ServiceStatus"

# B. Firewall Test
$NetTest = Test-NetConnection -ComputerName $SPLUNK_SERVER_IP -Port $SPLUNK_RECEIVE_PORT
if ($NetTest.TcpTestSucceeded) {
    Write-Host "2. Firewall Test:    PASS (Connected to $SPLUNK_SERVER_IP)" -ForegroundColor Green
} else {
    Write-Host "2. Firewall Test:    FAIL (Blocked by Firewall!)" -ForegroundColor Red
}

# C. Splunk Internal Connection Status
Write-Host "3. Forwarder Status: " -NoNewline
try {
    & $SPLUNK_BIN list forward-server -auth "${UF_ADMIN}:${PLAIN_PASS}" | Out-String | Write-Host
} catch {
    Write-Host "Could not query status (Check password)" -ForegroundColor Red
}

# Cleanup
Remove-Item $TEMP_MSI -ErrorAction SilentlyContinue
Write-Host "==================================================" -ForegroundColor Yellow
