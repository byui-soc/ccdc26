# CCDC26 Windows Toolkit - Splunk Universal Forwarder Setup
# PowerShell script to deploy Splunk UF on Windows systems
# Run as Administrator

#=============================================================================
# CONFIGURATION - UPDATE THESE VALUES FOR YOUR ENVIRONMENT
#=============================================================================
$SPLUNK_SERVER = "CHANGE_ME"         # IP or hostname of Splunk indexer
$SPLUNK_PORT = "9997"                 # Default receiving port
$SPLUNK_HOME = "C:\Program Files\SplunkUniversalForwarder"
$SPLUNK_VERSION = "9.2.0"
$SPLUNK_BUILD = "2f6451c60e37"

# Download URL
$SPLUNK_MSI_URL = "https://download.splunk.com/products/universalforwarder/releases/$SPLUNK_VERSION/windows/splunkforwarder-$SPLUNK_VERSION-$SPLUNK_BUILD-x64-release.msi"

#=============================================================================
# VALIDATION
#=============================================================================
function Test-Configuration {
    if ($SPLUNK_SERVER -eq "CHANGE_ME") {
        Write-Host "[ERROR] SPLUNK_SERVER is not configured!" -ForegroundColor Red
        Write-Host "[INFO] Edit this script and set SPLUNK_SERVER to your Splunk indexer IP/hostname" -ForegroundColor Yellow
        exit 1
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[ERROR] This script must be run as Administrator" -ForegroundColor Red
        exit 1
    }
}

#=============================================================================
# DOWNLOAD AND INSTALL
#=============================================================================
function Install-SplunkForwarder {
    Write-Host "`n=== Installing Splunk Universal Forwarder ===" -ForegroundColor Cyan

    # Check if already installed
    if (Test-Path "$SPLUNK_HOME\bin\splunk.exe") {
        Write-Host "[INFO] Splunk Forwarder already installed" -ForegroundColor Yellow
        return
    }

    # Download
    $downloadPath = "$env:TEMP\splunkforwarder.msi"
    Write-Host "[INFO] Downloading Splunk Universal Forwarder..." -ForegroundColor Blue

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $SPLUNK_MSI_URL -OutFile $downloadPath -UseBasicParsing
    }
    catch {
        Write-Host "[ERROR] Failed to download Splunk Forwarder" -ForegroundColor Red
        Write-Host "[INFO] Please download manually from: https://www.splunk.com/en_us/download/universal-forwarder.html" -ForegroundColor Yellow
        exit 1
    }

    # Generate admin password
    $adminPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | ForEach-Object {[char]$_})

    # Install silently
    Write-Host "[INFO] Installing Splunk Forwarder..." -ForegroundColor Blue
    $installArgs = @(
        "/i", $downloadPath,
        "AGREETOLICENSE=Yes",
        "SPLUNKUSERNAME=admin",
        "SPLUNKPASSWORD=$adminPassword",
        "RECEIVING_INDEXER=${SPLUNK_SERVER}:${SPLUNK_PORT}",
        "/quiet"
    )

    Start-Process msiexec.exe -ArgumentList $installArgs -Wait -NoNewWindow

    # Cleanup
    Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue

    # Save credentials
    "$adminPassword" | Out-File "$SPLUNK_HOME\admin_password.txt" -Force

    Write-Host "[OK] Splunk Forwarder installed" -ForegroundColor Green
    Write-Host "[INFO] Admin password saved to: $SPLUNK_HOME\admin_password.txt" -ForegroundColor Yellow
}

#=============================================================================
# CONFIGURE INPUTS - WINDOWS EVENT LOGS
#=============================================================================
function Configure-Inputs {
    Write-Host "`n=== Configuring Windows Event Log Inputs ===" -ForegroundColor Cyan

    $inputsDir = "$SPLUNK_HOME\etc\system\local"
    if (-not (Test-Path $inputsDir)) {
        New-Item -ItemType Directory -Path $inputsDir -Force | Out-Null
    }

    $hostname = $env:COMPUTERNAME

    $inputsConf = @"
# CCDC Windows Splunk Forwarder Inputs Configuration
# Generated: $(Get-Date)
# Host: $hostname

#=============================================================================
# GLOBAL SETTINGS
#=============================================================================
[default]
host = $hostname
index = wineventlog

#=============================================================================
# WINDOWS SECURITY EVENT LOG - Critical for security monitoring
#=============================================================================
[WinEventLog://Security]
disabled = false
index = security
sourcetype = WinEventLog:Security
evt_resolve_ad_obj = 1
checkpointInterval = 5
# Key events: 4624 (logon), 4625 (failed logon), 4648 (explicit creds),
# 4672 (special privs), 4720 (user created), 4732 (added to group)

#=============================================================================
# WINDOWS SYSTEM EVENT LOG
#=============================================================================
[WinEventLog://System]
disabled = false
index = wineventlog
sourcetype = WinEventLog:System
checkpointInterval = 5

#=============================================================================
# WINDOWS APPLICATION EVENT LOG
#=============================================================================
[WinEventLog://Application]
disabled = false
index = wineventlog
sourcetype = WinEventLog:Application
checkpointInterval = 5

#=============================================================================
# WINDOWS POWERSHELL LOG
#=============================================================================
[WinEventLog://Windows PowerShell]
disabled = false
index = security
sourcetype = WinEventLog:PowerShell
checkpointInterval = 5

#=============================================================================
# POWERSHELL OPERATIONAL LOG (Script Block Logging)
#=============================================================================
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = false
index = security
sourcetype = WinEventLog:PowerShell:Operational
checkpointInterval = 5

#=============================================================================
# WINDOWS DEFENDER
#=============================================================================
[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = false
index = security
sourcetype = WinEventLog:Defender
checkpointInterval = 5

#=============================================================================
# WINDOWS FIREWALL
#=============================================================================
[WinEventLog://Microsoft-Windows-Windows Firewall With Advanced Security/Firewall]
disabled = false
index = security
sourcetype = WinEventLog:Firewall
checkpointInterval = 5

#=============================================================================
# SYSMON (if installed - highly recommended!)
#=============================================================================
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = security
sourcetype = WinEventLog:Sysmon
checkpointInterval = 5
renderXml = true

#=============================================================================
# TASK SCHEDULER
#=============================================================================
[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = false
index = security
sourcetype = WinEventLog:TaskScheduler
checkpointInterval = 5

#=============================================================================
# REMOTE DESKTOP SERVICES
#=============================================================================
[WinEventLog://Microsoft-Windows-TerminalServices-LocalSessionManager/Operational]
disabled = false
index = security
sourcetype = WinEventLog:RDP
checkpointInterval = 5

[WinEventLog://Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational]
disabled = false
index = security
sourcetype = WinEventLog:RDP
checkpointInterval = 5

#=============================================================================
# DNS SERVER (if DNS role installed)
#=============================================================================
[WinEventLog://DNS Server]
disabled = false
index = dns
sourcetype = WinEventLog:DNS
checkpointInterval = 5

#=============================================================================
# ACTIVE DIRECTORY (if DC)
#=============================================================================
[WinEventLog://Directory Service]
disabled = false
index = security
sourcetype = WinEventLog:DirectoryService
checkpointInterval = 5

#=============================================================================
# IIS LOGS (if IIS installed)
#=============================================================================
[monitor://C:\inetpub\logs\LogFiles\*\*.log]
disabled = false
index = web
sourcetype = iis
ignoreOlderThan = 7d

#=============================================================================
# DHCP SERVER LOGS
#=============================================================================
[monitor://C:\Windows\System32\dhcp\*.log]
disabled = false
index = os
sourcetype = dhcp

#=============================================================================
# WINDOWS UPDATE LOG
#=============================================================================
[WinEventLog://Microsoft-Windows-WindowsUpdateClient/Operational]
disabled = false
index = os
sourcetype = WinEventLog:WindowsUpdate
checkpointInterval = 5

#=============================================================================
# BITS (Background Intelligent Transfer Service)
#=============================================================================
[WinEventLog://Microsoft-Windows-Bits-Client/Operational]
disabled = false
index = security
sourcetype = WinEventLog:BITS
checkpointInterval = 5

#=============================================================================
# WINEVENT CODE INTEGRITY
#=============================================================================
[WinEventLog://Microsoft-Windows-CodeIntegrity/Operational]
disabled = false
index = security
sourcetype = WinEventLog:CodeIntegrity
checkpointInterval = 5

"@

    $inputsConf | Out-File "$inputsDir\inputs.conf" -Encoding ASCII -Force
    Write-Host "[OK] Inputs configured for Windows Event Logs" -ForegroundColor Green
}

#=============================================================================
# CONFIGURE OUTPUTS
#=============================================================================
function Configure-Outputs {
    Write-Host "`n=== Configuring Splunk Outputs ===" -ForegroundColor Cyan

    $outputsDir = "$SPLUNK_HOME\etc\system\local"
    if (-not (Test-Path $outputsDir)) {
        New-Item -ItemType Directory -Path $outputsDir -Force | Out-Null
    }

    $outputsConf = @"
# CCDC Splunk Forwarder Outputs Configuration
# Generated: $(Get-Date)

[tcpout]
defaultGroup = ccdc-indexers

[tcpout:ccdc-indexers]
server = ${SPLUNK_SERVER}:${SPLUNK_PORT}
compressed = true
useACK = true

"@

    $outputsConf | Out-File "$outputsDir\outputs.conf" -Encoding ASCII -Force
    Write-Host "[OK] Outputs configured: ${SPLUNK_SERVER}:${SPLUNK_PORT}" -ForegroundColor Green
}

#=============================================================================
# ENABLE POWERSHELL LOGGING
#=============================================================================
function Enable-PowerShellLogging {
    Write-Host "`n=== Enabling PowerShell Logging ===" -ForegroundColor Cyan

    # Enable Script Block Logging
    $sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $sbPath)) {
        New-Item -Path $sbPath -Force | Out-Null
    }
    Set-ItemProperty -Path $sbPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

    # Enable Module Logging
    $mlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $mlPath)) {
        New-Item -Path $mlPath -Force | Out-Null
    }
    Set-ItemProperty -Path $mlPath -Name "EnableModuleLogging" -Value 1 -Type DWord

    # Log all modules
    $mlModulesPath = "$mlPath\ModuleNames"
    if (-not (Test-Path $mlModulesPath)) {
        New-Item -Path $mlModulesPath -Force | Out-Null
    }
    Set-ItemProperty -Path $mlModulesPath -Name "*" -Value "*" -Type String

    Write-Host "[OK] PowerShell Script Block and Module Logging enabled" -ForegroundColor Green
}

#=============================================================================
# ENABLE COMMAND LINE AUDITING
#=============================================================================
function Enable-CommandLineAuditing {
    Write-Host "`n=== Enabling Command Line Auditing ===" -ForegroundColor Cyan

    # Enable command line in process creation events
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

    # Enable Process Creation auditing via auditpol
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null

    Write-Host "[OK] Command line auditing enabled" -ForegroundColor Green
}

#=============================================================================
# START SPLUNK FORWARDER
#=============================================================================
function Start-SplunkForwarder {
    Write-Host "`n=== Starting Splunk Forwarder ===" -ForegroundColor Cyan

    & "$SPLUNK_HOME\bin\splunk.exe" start

    Start-Sleep -Seconds 3

    $service = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host "[OK] Splunk Forwarder is running" -ForegroundColor Green
    }
    else {
        Write-Host "[WARN] Splunk Forwarder may not be running. Check services." -ForegroundColor Yellow
    }
}

#=============================================================================
# CHECK STATUS
#=============================================================================
function Get-ForwarderStatus {
    Write-Host "`n=== Splunk Forwarder Status ===" -ForegroundColor Cyan

    if (-not (Test-Path "$SPLUNK_HOME\bin\splunk.exe")) {
        Write-Host "[ERROR] Splunk Forwarder not installed" -ForegroundColor Red
        return
    }

    & "$SPLUNK_HOME\bin\splunk.exe" status

    Write-Host "`n[INFO] Forwarding to: ${SPLUNK_SERVER}:${SPLUNK_PORT}" -ForegroundColor Blue

    Write-Host "`n[INFO] Configured inputs:" -ForegroundColor Blue
    Get-Content "$SPLUNK_HOME\etc\system\local\inputs.conf" -ErrorAction SilentlyContinue |
        Select-String "^\[" |
        ForEach-Object { Write-Host "  $_" }
}

#=============================================================================
# TEST CONNECTIVITY
#=============================================================================
function Test-SplunkConnectivity {
    Write-Host "`n=== Testing Splunk Server Connectivity ===" -ForegroundColor Cyan

    if ($SPLUNK_SERVER -eq "CHANGE_ME") {
        Write-Host "[ERROR] SPLUNK_SERVER not configured" -ForegroundColor Red
        return
    }

    Write-Host "[INFO] Testing connection to ${SPLUNK_SERVER}:${SPLUNK_PORT}..." -ForegroundColor Blue

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($SPLUNK_SERVER, [int]$SPLUNK_PORT)
        $tcpClient.Close()
        Write-Host "[OK] Connection to ${SPLUNK_SERVER}:${SPLUNK_PORT} successful" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Cannot connect to ${SPLUNK_SERVER}:${SPLUNK_PORT}" -ForegroundColor Red
        Write-Host "[INFO] Ensure the Splunk indexer is running and port $SPLUNK_PORT is open" -ForegroundColor Yellow
    }
}

#=============================================================================
# QUICK SETUP
#=============================================================================
function Invoke-QuickSetup {
    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host "  CCDC Windows Splunk Forwarder Setup" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan

    Test-Administrator
    Test-Configuration

    Install-SplunkForwarder
    Configure-Outputs
    Configure-Inputs
    Enable-PowerShellLogging
    Enable-CommandLineAuditing
    Start-SplunkForwarder

    Write-Host "`n============================================" -ForegroundColor Green
    Write-Host "  Setup Complete!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Forwarding to: ${SPLUNK_SERVER}:${SPLUNK_PORT}" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Windows Event Logs being forwarded:" -ForegroundColor Yellow
    Write-Host "  - Security (logons, auth, privilege use)"
    Write-Host "  - System"
    Write-Host "  - Application"
    Write-Host "  - PowerShell (script block logging)"
    Write-Host "  - Windows Defender"
    Write-Host "  - Windows Firewall"
    Write-Host "  - Sysmon (if installed)"
    Write-Host "  - Task Scheduler"
    Write-Host "  - Remote Desktop"
    Write-Host "  - DNS Server (if DC)"
    Write-Host "  - Active Directory (if DC)"
    Write-Host "  - IIS Logs (if present)"
    Write-Host ""
    Write-Host "[TIP] Install Sysmon for enhanced logging:" -ForegroundColor Cyan
    Write-Host "  https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"
}

#=============================================================================
# MAIN MENU
#=============================================================================
function Show-Menu {
    Write-Host ""
    Write-Host "Splunk Universal Forwarder Options:" -ForegroundColor Cyan
    Write-Host "1) Quick setup (full installation)"
    Write-Host "2) Check status"
    Write-Host "3) Test server connectivity"
    Write-Host "4) Start forwarder"
    Write-Host "5) Stop forwarder"
    Write-Host "6) Restart forwarder"
    Write-Host "7) View recent events sent"
    Write-Host ""

    $choice = Read-Host "Select option [1-7]"

    switch ($choice) {
        "1" { Invoke-QuickSetup }
        "2" { Get-ForwarderStatus }
        "3" { Test-SplunkConnectivity }
        "4" { & "$SPLUNK_HOME\bin\splunk.exe" start }
        "5" { & "$SPLUNK_HOME\bin\splunk.exe" stop }
        "6" { & "$SPLUNK_HOME\bin\splunk.exe" restart }
        "7" { Get-Content "$SPLUNK_HOME\var\log\splunk\splunkd.log" -Tail 50 }
        default { Write-Host "[ERROR] Invalid option" -ForegroundColor Red }
    }
}

# Run if executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Show-Menu
}
