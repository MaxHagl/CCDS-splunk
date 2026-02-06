# ==============================================================================
# Splunk Universal Forwarder Installer (Debug Edition)
# Fixes: Infinite loop hang & Silent MSI failures & Windows 11 TLS issues
# ==============================================================================

#Requires -RunAsAdministrator

# Check if running as admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Script must run as Administrator!" -ForegroundColor Red
    Write-Host "[!] Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

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

# --- Force TLS 1.2 (Required for Windows 11) ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Credentials ---
Write-Host "`n--- Credentials Setup ---" -ForegroundColor Cyan
Write-Host "NOTE: Password must contain Upper, Lower, Number, and Symbol!" -ForegroundColor Yellow
$UF_ADMIN = Read-Host -Prompt "Enter NEW Splunk Forwarder local admin username [admin]"
if ([string]::IsNullOrWhiteSpace($UF_ADMIN)) { $UF_ADMIN = "admin" }
$UF_PASS = Read-Host -Prompt "Enter NEW Splunk Forwarder local admin password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UF_PASS)
$PLAIN_PASS = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# --- 1. Download MSI ---
Write-Host "`n[*] Downloading Splunk Universal Forwarder MSI..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $MSI_URL -OutFile $TEMP_MSI -ErrorAction Stop
    Write-Host "[✓] Download completed: $TEMP_MSI" -ForegroundColor Green
} catch {
    Write-Host "[!] Download Failed!" -ForegroundColor Red
    Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[!] Check internet connection or URL." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

# Verify file exists and has size
if (-not (Test-Path $TEMP_MSI)) {
    Write-Host "[!] MSI file was not created!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit
}

$fileSize = (Get-Item $TEMP_MSI).Length / 1MB
Write-Host "[*] Downloaded file size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Cyan
if ($fileSize -lt 10) {
    Write-Host "[!] WARNING: File seems too small. Download may have failed." -ForegroundColor Yellow
    Read-Host "Press Enter to continue anyway or Ctrl+C to cancel"
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
    if (Test-Path $INSTALL_LOG) {
        Get-Content $INSTALL_LOG | Select-String "Return value 3|error|failed" -Context 5 | Out-String | Write-Host
        Write-Host "[*] Full Log available at: $INSTALL_LOG" -ForegroundColor Cyan
    } else {
        Write-Host "[!] Log file not found at: $INSTALL_LOG" -ForegroundColor Red
    }
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "[✓] Installation completed successfully" -ForegroundColor Green

# --- 3. FIX: Configure inputs.conf (With Timeout) ---
Write-Host "[*] Configuring inputs.conf (Enabling Windows Logs)..." -ForegroundColor Cyan

# Wait loop with Timeout (Max 30 seconds)
$timeout = 0
while (-not (Test-Path "$SPLUNK_HOME\etc\system\local")) { 
    Start-Sleep -Seconds 2
    $timeout++
    Write-Host "    Waiting for installation to complete... ($($timeout * 2)s)" -ForegroundColor Gray
    if ($timeout -ge 15) {
        Write-Host "[!] TIMEOUT: Installation folder never appeared." -ForegroundColor Red
        Write-Host "[!] The password was likely too weak or the installer crashed." -ForegroundColor Red
        Write-Host "[*] Check log: $INSTALL_LOG" -ForegroundColor Cyan
        Read-Host "Press Enter to exit"
        exit
    }
}

Write-Host "[✓] Installation directory confirmed" -ForegroundColor Green

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
Write-Host "[✓] inputs.conf configured" -ForegroundColor Green

# --- 4. Patch server.conf ---
Write-Host "[*] Patching server.conf to allow login..." -ForegroundColor Cyan
if (-not (Test-Path $SERVER_CONF)) {
    Set-Content -Path $SERVER_CONF -Value "[general]`r`nallowRemoteLogin = always"
} else {
    Add-Content -Path $SERVER_CONF -Value "`r`n[general]`r`nallowRemoteLogin = always"
}
Write-Host "[✓] server.conf patched" -ForegroundColor Green

# --- 5. Restart & Verify ---
Write-Host "[*] Restarting Splunk Service..." -ForegroundColor Cyan
try {
    Restart-Service -Name SplunkForwarder -Force -ErrorAction Stop
    Start-Sleep -Seconds 5
    Write-Host "[✓] Service restarted successfully" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to restart service: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[*] You may need to restart manually" -ForegroundColor Yellow
}

Write-Host "`n==================================================" -ForegroundColor Yellow
Write-Host "             FINAL VERIFICATION"
Write-Host "==================================================" -ForegroundColor Yellow

# Check service status
$service = Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Service Status:   $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Red' })
} else {
    Write-Host "Service Status:   NOT FOUND" -ForegroundColor Red
}

# Network test
Write-Host "Testing connection to Splunk Server..." -ForegroundColor Cyan
$NetTest = Test-NetConnection -ComputerName $SPLUNK_SERVER_IP -Port $SPLUNK_RECEIVE_PORT
if ($NetTest.TcpTestSucceeded) {
    Write-Host "Firewall Test:    PASS" -ForegroundColor Green
} else {
    Write-Host "Firewall Test:    FAIL" -ForegroundColor Red
    Write-Host "                  Check firewall rules or server availability" -ForegroundColor Yellow
}

# Cleanup
Remove-Item $TEMP_MSI -ErrorAction SilentlyContinue

Write-Host "`n==================================================" -ForegroundColor Yellow
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "Log file: $INSTALL_LOG" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Yellow

Read-Host "`nPress Enter to exit"
