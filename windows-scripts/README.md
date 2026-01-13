# CCDC26 Windows Defense Scripts

PowerShell scripts for Windows system hardening and log forwarding during CCDC competition.

## Scripts

### Install-SplunkForwarder.ps1
Deploys Splunk Universal Forwarder on Windows systems with comprehensive event log collection.

**Setup:**
1. Edit the script and set `$SPLUNK_SERVER` to your Splunk indexer IP
2. Run as Administrator: `.\Install-SplunkForwarder.ps1`
3. Select option 1 for quick setup

**Windows Event Logs Collected:**
- Security (logons, failed logons, privilege use, account changes)
- System (services, errors)
- Application
- PowerShell (script block logging enabled)
- Windows Defender
- Windows Firewall
- Sysmon (if installed - highly recommended!)
- Task Scheduler
- Remote Desktop Services
- DNS Server (if DC)
- Active Directory (if DC)
- IIS Logs (if present)
- DHCP Logs
- BITS

**Enhanced Logging Enabled:**
- PowerShell Script Block Logging
- PowerShell Module Logging
- Command Line in Process Creation events

## Requirements
- Windows Server 2012+ or Windows 10+
- PowerShell 5.0+
- Administrator privileges
- Network access to Splunk indexer

## Sysmon Recommendation
For enhanced visibility, install Sysmon:
```powershell
# Download from Microsoft Sysinternals
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with default config
sysmon64.exe -accepteula -i

# Or use a community config (recommended)
# https://github.com/SwiftOnSecurity/sysmon-config
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
