# ===========================
# Splunk Universal Forwarder Installer (Windows 11 / Server 2019)
# ===========================

# --- CONFIGURATION ---
$SPLUNK_SERVER_IP = "172.20.242.20"
$SPLUNK_RECEIVE_PORT = "9997"
# Verified stable link for v10.0.3 (x64)
$MSI_URL = "https://download.splunk.com/products/universalforwarder/releases/10.0.3/windows/splunkforwarder-10.0.3-adbac1c8811c-windows-x64.msi"
$TEMP_MSI = "$env:TEMP\splunk_uf.msi"

# --- Credentials ---
$UF_ADMIN = Read-Host -Prompt "Enter NEW Splunk Forwarder local admin username [admin]"
if ([string]::IsNullOrWhiteSpace($UF_ADMIN)) { $UF_ADMIN = "admin" }
$UF_PASS = Read-Host -Prompt "Enter NEW Splunk Forwarder local admin password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UF_PASS)
$PLAIN_PASS = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# --- 1. Download MSI ---
Write-Host "[*] Downloading Splunk Universal Forwarder MSI..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $MSI_URL -OutFile $TEMP_MSI -ErrorAction Stop
} catch {
    Write-Host "[!] Download Failed! Check your internet connection or URL." -ForegroundColor Red
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
    "SPLUNKPASSWORD=`"$PLAIN_PASS`""
)

Start-Process msiexec.exe -ArgumentList $MSIArgs -Wait

# --- 3. Verification ---
$SPLUNK_BIN = "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe"
Start-Sleep -Seconds 5
Write-Host "`n--------------------------------------------------" -ForegroundColor Yellow
Write-Host "Installation Complete."
Write-Host "Service Status: $(Get-Service -Name SplunkForwarder | Select-Object -ExpandProperty Status)"
Write-Host "--------------------------------------------------" -ForegroundColor Yellow

# Cleanup
Remove-Item $TEMP_MSI -ErrorAction SilentlyContinue
