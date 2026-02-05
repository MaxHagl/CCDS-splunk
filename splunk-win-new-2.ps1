# ==============================================================================
# Splunk Universal Forwarder Installer (Debug Edition)
# Fixes: Infinite loop hang & Silent MSI failures
# ==============================================================================

# --- CONFIGURATION ---
$SPLUNK_SERVER_IP = "172.20.242.20"
$SPLUNK_RECEIVE_PORT = "9997"
$MSI_URL = "https://download.splunk.com/products/universalforwarder/releases/10.0.3/windows/splunkforwarder-10.0.3-adbac1c8811c-windows-x64.msi"
$TEMP_MSI = "$env:TEMP\splunk_uf.msi"
$INSTALL_LOG = "$env:TEMP\splunk_install.log"

# Paths
$SPLUNK_HOME = "C:\Program Files\SplunkUniversalForwarder"
$SPLUNK_BIN = "$SPLUNK_HOME\bin\splunk.exe"
$INPUTS_CONF = "$SPLUNK_HOME\etc\system\local\inputs.conf"
$SERVER_CONF = "$SPLUNK_HOME\etc\system\local\server.conf"

# --- Credentials ---
Write-Host "`n--- Credentials Setup ---" -ForegroundColor Cyan
Write-Host "NOTE: Password must contain Upper, Lower, Number, and Symbol!" -ForegroundColor Yellow
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

# --- 2. Silent Installation (With Logging) ---
Write-Host "[*] Installing Splunk Forwarder..." -ForegroundColor Cyan
$MSIArgs = @(
    "/i", "`"$TEMP_MSI`"",
    "/quiet",
    "/L*v", "`"$INSTALL_LOG`"",  # <--- Generating Log File
    "AGREETOLICENSE=Yes",
    "RECEIVING_INDEXER=`"$($SPLUNK_SERVER_IP):$($SPLUNK_RECEIVE_PORT)`"",
    "LAUNCHSPLUNK=1",
    "SPLUNKPASSWORD=`"$PLAIN_PASS`"",
    "SPLUNKUSERNAME=`"$UF_ADMIN`""
)

$process = Start-Process msiexec.exe -ArgumentList $MSIArgs -Wait -PassThru

if ($process.ExitCode -ne 0) {
    Write-Host "[!] Installation FAILED with exit code $($process.ExitCode)" -ForegroundColor Red
    Write-Host "[!] Checking Log file for errors..." -ForegroundColor Yellow
    Get-Content $INSTALL_LOG | Select-String "Return value 3" -Context 5 | Out-String | Write-Host
    Write-Host "[*] Full Log available at: $INSTALL_LOG"
    exit
}

# --- 3. FIX: Configure inputs.conf (With Timeout) ---
Write-Host "[*] Configuring inputs.conf (Enabling Windows Logs)..." -ForegroundColor Cyan

# Wait loop with Timeout (Max 30 seconds)
$timeout = 0
while (-not (Test-Path "$SPLUNK_HOME\etc\system\local")) { 
    Start-Sleep -Seconds 2
    $timeout++
    if ($timeout -ge 15) {
        Write-Host "[!] TIMEOUT: Installation folder never appeared." -ForegroundColor Red
        Write-Host "[!] The password might was likely too weak or the installer crashed." -ForegroundColor Red
        Write-Host "[*] Check log: $INSTALL_LOG"
        exit
    }
}

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

# --- 4. Patch server.conf ---
Write-Host "[*] Patching server.conf to allow login..." -ForegroundColor Cyan
if (-not (Test-Path $SERVER_CONF)) {
    Set-Content -Path $SERVER_CONF -Value "[general]`r`nallowRemoteLogin = always"
} else {
    Add-Content -Path $SERVER_CONF -Value "`r`n[general]`r`nallowRemoteLogin = always"
}

# --- 5. Restart & Verify ---
Write-Host "[*] Restarting Splunk Service..." -ForegroundColor Cyan
Restart-Service -Name SplunkForwarder -Force
Start-Sleep -Seconds 5

Write-Host "`n==================================================" -ForegroundColor Yellow
Write-Host "             FINAL VERIFICATION"
Write-Host "==================================================" -ForegroundColor Yellow

$NetTest = Test-NetConnection -ComputerName $SPLUNK_SERVER_IP -Port $SPLUNK_RECEIVE_PORT
if ($NetTest.TcpTestSucceeded) {
    Write-Host "Firewall Test:    PASS" -ForegroundColor Green
} else {
    Write-Host "Firewall Test:    FAIL" -ForegroundColor Red
}

Remove-Item $TEMP_MSI -ErrorAction SilentlyContinue
