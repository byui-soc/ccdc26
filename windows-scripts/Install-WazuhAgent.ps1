# CCDC26 Windows Toolkit - Wazuh Agent Setup
# PowerShell script to deploy Wazuh Agent on Windows systems
# Run as Administrator

#=============================================================================
# CONFIGURATION - UPDATE THESE VALUES FOR YOUR ENVIRONMENT
#=============================================================================
$WAZUH_MANAGER = "CHANGE_ME"         # IP or hostname of Wazuh manager
$WAZUH_REGISTRATION_PASSWORD = ""     # Optional: registration password
$WAZUH_AGENT_GROUP = "windows"        # Agent group
$WAZUH_VERSION = "4.7.2"

# Paths
$WAZUH_HOME = "C:\Program Files (x86)\ossec-agent"
$WAZUH_CONF = "$WAZUH_HOME\ossec.conf"

# Download URL
$WAZUH_MSI_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VERSION-1.msi"

#=============================================================================
# VALIDATION
#=============================================================================
function Test-Configuration {
    if ($WAZUH_MANAGER -eq "CHANGE_ME") {
        Write-Host "[ERROR] WAZUH_MANAGER is not configured!" -ForegroundColor Red
        Write-Host "[INFO] Edit this script and set WAZUH_MANAGER to your Wazuh manager IP/hostname" -ForegroundColor Yellow
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
function Install-WazuhAgent {
    Write-Host "`n=== Installing Wazuh Agent ===" -ForegroundColor Cyan

    # Check if already installed
    if (Test-Path "$WAZUH_HOME\wazuh-agent.exe") {
        Write-Host "[INFO] Wazuh Agent already installed at $WAZUH_HOME" -ForegroundColor Yellow
        return
    }

    # Download
    $downloadPath = "$env:TEMP\wazuh-agent.msi"
    Write-Host "[INFO] Downloading Wazuh Agent v$WAZUH_VERSION..." -ForegroundColor Blue

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Use BITS for more reliable download
        $bitsJob = Start-BitsTransfer -Source $WAZUH_MSI_URL -Destination $downloadPath -ErrorAction SilentlyContinue
        
        if (-not (Test-Path $downloadPath)) {
            # Fallback to WebClient
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($WAZUH_MSI_URL, $downloadPath)
        }
    }
    catch {
        Write-Host "[ERROR] Failed to download Wazuh Agent" -ForegroundColor Red
        Write-Host "[INFO] Please download manually from: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html" -ForegroundColor Yellow
        exit 1
    }

    # Install silently with manager configuration
    Write-Host "[INFO] Installing Wazuh Agent..." -ForegroundColor Blue
    
    $installArgs = @(
        "/i", $downloadPath,
        "/q",
        "WAZUH_MANAGER=`"$WAZUH_MANAGER`"",
        "WAZUH_AGENT_GROUP=`"$WAZUH_AGENT_GROUP`""
    )

    # Add registration password if configured
    if (-not [string]::IsNullOrEmpty($WAZUH_REGISTRATION_PASSWORD)) {
        $installArgs += "WAZUH_REGISTRATION_PASSWORD=`"$WAZUH_REGISTRATION_PASSWORD`""
    }

    Start-Process msiexec.exe -ArgumentList $installArgs -Wait -NoNewWindow

    # Cleanup
    Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue

    if (Test-Path "$WAZUH_HOME\wazuh-agent.exe") {
        Write-Host "[OK] Wazuh Agent installed" -ForegroundColor Green
    }
    else {
        Write-Host "[ERROR] Installation may have failed. Check $WAZUH_HOME" -ForegroundColor Red
    }
}

#=============================================================================
# CONFIGURE AGENT
#=============================================================================
function Configure-WazuhAgent {
    Write-Host "`n=== Configuring Wazuh Agent ===" -ForegroundColor Cyan

    $hostname = $env:COMPUTERNAME

    # Create comprehensive ossec.conf
    $ossecConf = @"
<!--
  CCDC26 Wazuh Agent Configuration for Windows
  Generated: $(Get-Date)
  Manager: $WAZUH_MANAGER
  Host: $hostname
-->

<ossec_config>
  <client>
    <server>
      <address>$WAZUH_MANAGER</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>windows</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Windows Event Log Collection -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4670 and EventID != 4690 and EventID != 4703]</query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- PowerShell Logging -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Windows PowerShell</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Sysmon (if installed) -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Windows Defender -->
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Windows Firewall -->
  <localfile>
    <location>Microsoft-Windows-Windows Firewall With Advanced Security/Firewall</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Task Scheduler -->
  <localfile>
    <location>Microsoft-Windows-TaskScheduler/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Remote Desktop -->
  <localfile>
    <location>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- DNS Server (if installed) -->
  <localfile>
    <location>DNS Server</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Active Directory (if DC) -->
  <localfile>
    <location>Directory Service</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Code Integrity -->
  <localfile>
    <location>Microsoft-Windows-CodeIntegrity/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- BITS -->
  <localfile>
    <location>Microsoft-Windows-Bits-Client/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- IIS Logs (if installed) -->
  <localfile>
    <location>C:\inetpub\logs\LogFiles\*\*.log</location>
    <log_format>iis</log_format>
  </localfile>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>

    <!-- Critical Windows directories -->
    <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\SysWOW64</directories>
    <directories check_all="yes">C:\Windows\System32\drivers</directories>
    
    <!-- User startup folders -->
    <directories check_all="yes" realtime="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories check_all="yes" realtime="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>

    <!-- Web roots (if IIS) -->
    <directories check_all="yes" realtime="yes">C:\inetpub\wwwroot</directories>

    <!-- Critical files -->
    <directories check_all="yes" realtime="yes">C:\Windows\System32\config</directories>

    <!-- Registry monitoring -->
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDLLs</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>

    <!-- Ignore patterns -->
    <ignore type="sregex">.log$|.tmp$</ignore>
    <ignore>C:\Windows\System32\config\systemprofile</ignore>
    <ignore>C:\Windows\System32\wbem\Performance</ignore>
  </syscheck>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <windows_apps>yes</windows_apps>
    <windows_malware>yes</windows_malware>
    <frequency>43200</frequency>
  </rootcheck>

  <!-- System Inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <packages>yes</packages>
    <os>yes</os>
    <hotfixes>yes</hotfixes>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <!-- Security Configuration Assessment (CIS Benchmarks) -->
  <wodle name="sca">
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </wodle>

  <!-- Active Response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>wpk_root.pem</ca_store>
  </active-response>

  <!-- Logging -->
  <logging>
    <log_format>json</log_format>
  </logging>

</ossec_config>
"@

    $ossecConf | Out-File $WAZUH_CONF -Encoding UTF8 -Force
    Write-Host "[OK] Agent configuration created" -ForegroundColor Green
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
# ENABLE ADVANCED AUDITING
#=============================================================================
function Enable-AdvancedAuditing {
    Write-Host "`n=== Enabling Advanced Auditing ===" -ForegroundColor Cyan

    # Enable key audit policies
    $auditPolicies = @(
        "Logon",
        "Logoff",
        "Account Lockout",
        "Special Logon",
        "Process Creation",
        "Process Termination",
        "Security Group Management",
        "User Account Management",
        "Computer Account Management",
        "Security System Extension",
        "System Integrity",
        "Audit Policy Change",
        "Authentication Policy Change",
        "Sensitive Privilege Use",
        "Other Object Access Events",
        "Removable Storage",
        "File Share",
        "Filtering Platform Connection"
    )

    foreach ($policy in $auditPolicies) {
        auditpol /set /subcategory:"$policy" /success:enable /failure:enable 2>$null
    }

    Write-Host "[OK] Advanced audit policies enabled" -ForegroundColor Green
}

#=============================================================================
# REGISTER AGENT
#=============================================================================
function Register-WazuhAgent {
    Write-Host "`n=== Registering Agent with Manager ===" -ForegroundColor Cyan

    # Check if already registered
    $clientKeys = "$WAZUH_HOME\client.keys"
    if ((Test-Path $clientKeys) -and ((Get-Content $clientKeys -ErrorAction SilentlyContinue) -ne "")) {
        Write-Host "[INFO] Agent already registered" -ForegroundColor Yellow
        Get-Content $clientKeys
        return
    }

    # Try auto-enrollment
    $agentAuth = "$WAZUH_HOME\agent-auth.exe"
    if (Test-Path $agentAuth) {
        Write-Host "[INFO] Attempting auto-enrollment with manager..." -ForegroundColor Blue

        $authArgs = "-m $WAZUH_MANAGER -A $env:COMPUTERNAME"

        if (-not [string]::IsNullOrEmpty($WAZUH_REGISTRATION_PASSWORD)) {
            $authArgs += " -P $WAZUH_REGISTRATION_PASSWORD"
        }

        if ($WAZUH_AGENT_GROUP -ne "default") {
            $authArgs += " -G $WAZUH_AGENT_GROUP"
        }

        $process = Start-Process -FilePath $agentAuth -ArgumentList $authArgs -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Host "[OK] Agent registered successfully" -ForegroundColor Green
            if (Test-Path $clientKeys) {
                Get-Content $clientKeys
            }
        }
        else {
            Write-Host "[WARN] Auto-enrollment failed. Manual registration may be required." -ForegroundColor Yellow
            Write-Host "[INFO] On the Wazuh manager, run:" -ForegroundColor Blue
            Write-Host "  /var/ossec/bin/manage_agents"
            Write-Host "[INFO] Then import the key on this agent using:" -ForegroundColor Blue
            Write-Host "  & `"$WAZUH_HOME\manage_agents.exe`" -i <KEY>"
        }
    }
    else {
        Write-Host "[WARN] agent-auth.exe not found. Manual registration required." -ForegroundColor Yellow
    }
}

#=============================================================================
# START WAZUH AGENT
#=============================================================================
function Start-WazuhAgent {
    Write-Host "`n=== Starting Wazuh Agent ===" -ForegroundColor Cyan

    # Start the service
    Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 5

    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host "[OK] Wazuh Agent is running" -ForegroundColor Green
    }
    else {
        Write-Host "[WARN] Wazuh Agent may not be running. Check services." -ForegroundColor Yellow
        
        # Try starting via executable
        & "$WAZUH_HOME\wazuh-agent.exe" start
    }
}

#=============================================================================
# CHECK STATUS
#=============================================================================
function Get-AgentStatus {
    Write-Host "`n=== Wazuh Agent Status ===" -ForegroundColor Cyan

    if (-not (Test-Path "$WAZUH_HOME\wazuh-agent.exe")) {
        Write-Host "[ERROR] Wazuh Agent not installed" -ForegroundColor Red
        return
    }

    # Service status
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Service Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq "Running") { "Green" } else { "Red" })
    }

    Write-Host "`n[INFO] Manager: $WAZUH_MANAGER" -ForegroundColor Blue

    # Agent info
    Write-Host "`n[INFO] Agent Info:" -ForegroundColor Blue
    if (Test-Path "$WAZUH_HOME\client.keys") {
        Get-Content "$WAZUH_HOME\client.keys"
    }
    else {
        Write-Host "  Not registered" -ForegroundColor Yellow
    }

    # Connection status from logs
    Write-Host "`n[INFO] Recent Connection Status:" -ForegroundColor Blue
    if (Test-Path "$WAZUH_HOME\ossec.log") {
        Get-Content "$WAZUH_HOME\ossec.log" -Tail 20 | Select-String -Pattern "(Connected|Disconnected|ERROR)"
    }
}

#=============================================================================
# TEST CONNECTIVITY
#=============================================================================
function Test-WazuhConnectivity {
    Write-Host "`n=== Testing Wazuh Manager Connectivity ===" -ForegroundColor Cyan

    if ($WAZUH_MANAGER -eq "CHANGE_ME") {
        Write-Host "[ERROR] WAZUH_MANAGER not configured" -ForegroundColor Red
        return
    }

    # Test event port (1514)
    Write-Host "[INFO] Testing connection to ${WAZUH_MANAGER}:1514 (events)..." -ForegroundColor Blue
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($WAZUH_MANAGER, 1514)
        $tcpClient.Close()
        Write-Host "[OK] Connection to ${WAZUH_MANAGER}:1514 successful" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Cannot connect to ${WAZUH_MANAGER}:1514" -ForegroundColor Red
        Write-Host "[INFO] Ensure the Wazuh manager is running and port 1514 is open" -ForegroundColor Yellow
    }

    # Test enrollment port (1515)
    Write-Host "[INFO] Testing connection to ${WAZUH_MANAGER}:1515 (enrollment)..." -ForegroundColor Blue
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($WAZUH_MANAGER, 1515)
        $tcpClient.Close()
        Write-Host "[OK] Enrollment port ${WAZUH_MANAGER}:1515 accessible" -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Cannot connect to ${WAZUH_MANAGER}:1515" -ForegroundColor Yellow
        Write-Host "[INFO] Manual agent registration may be required" -ForegroundColor Yellow
    }
}

#=============================================================================
# QUICK SETUP
#=============================================================================
function Invoke-QuickSetup {
    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host "  CCDC Windows Wazuh Agent Setup" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan

    Test-Administrator
    Test-Configuration

    Install-WazuhAgent
    Configure-WazuhAgent
    Enable-PowerShellLogging
    Enable-CommandLineAuditing
    Enable-AdvancedAuditing
    Register-WazuhAgent
    Start-WazuhAgent

    Write-Host "`n============================================" -ForegroundColor Green
    Write-Host "  Setup Complete!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Manager: $WAZUH_MANAGER" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Windows Event Logs being collected:" -ForegroundColor Yellow
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
    Write-Host "Additional features enabled:" -ForegroundColor Yellow
    Write-Host "  - File Integrity Monitoring (FIM)"
    Write-Host "  - Registry Monitoring"
    Write-Host "  - Rootkit Detection"
    Write-Host "  - System Inventory"
    Write-Host "  - CIS Benchmark Assessment"
    Write-Host ""
    Write-Host "[TIP] Install Sysmon for enhanced logging:" -ForegroundColor Cyan
    Write-Host "  https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"
    Write-Host ""
    Write-Host "[TIP] Verify agent appears in Wazuh Dashboard under Agents" -ForegroundColor Cyan
}

#=============================================================================
# UNINSTALL
#=============================================================================
function Uninstall-WazuhAgent {
    Write-Host "`n=== Uninstalling Wazuh Agent ===" -ForegroundColor Cyan

    $confirm = Read-Host "Are you sure you want to uninstall? [y/N]"
    if ($confirm -ne "y" -and $confirm -ne "Y") {
        return
    }

    # Stop service
    Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue

    # Uninstall via MSI
    $uninstallKey = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                    Where-Object { $_.DisplayName -like "*Wazuh*" }

    if ($uninstallKey) {
        $uninstallString = $uninstallKey.UninstallString
        if ($uninstallString -match "msiexec") {
            $productCode = $uninstallKey.PSChildName
            Start-Process msiexec.exe -ArgumentList "/x $productCode /q" -Wait
        }
    }

    # Remove directory
    if (Test-Path $WAZUH_HOME) {
        Remove-Item -Path $WAZUH_HOME -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[OK] Wazuh Agent uninstalled" -ForegroundColor Green
}

#=============================================================================
# MAIN MENU
#=============================================================================
function Show-Menu {
    Write-Host ""
    Write-Host "Wazuh Agent Options:" -ForegroundColor Cyan
    Write-Host "1) Quick setup (full installation)"
    Write-Host "2) Check status"
    Write-Host "3) Test manager connectivity"
    Write-Host "4) Register agent"
    Write-Host "5) Start agent"
    Write-Host "6) Stop agent"
    Write-Host "7) Restart agent"
    Write-Host "8) View recent logs"
    Write-Host "9) Uninstall"
    Write-Host ""

    $choice = Read-Host "Select option [1-9]"

    switch ($choice) {
        "1" { Invoke-QuickSetup }
        "2" { Get-AgentStatus }
        "3" { Test-WazuhConnectivity }
        "4" { Register-WazuhAgent }
        "5" { Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue; Write-Host "Agent started" -ForegroundColor Green }
        "6" { Stop-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue; Write-Host "Agent stopped" -ForegroundColor Yellow }
        "7" { Restart-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue; Write-Host "Agent restarted" -ForegroundColor Green }
        "8" { if (Test-Path "$WAZUH_HOME\ossec.log") { Get-Content "$WAZUH_HOME\ossec.log" -Tail 50 } else { Write-Host "Log file not found" -ForegroundColor Yellow } }
        "9" { Uninstall-WazuhAgent }
        default { Write-Host "[ERROR] Invalid option" -ForegroundColor Red }
    }
}

# Run if executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Show-Menu
}
