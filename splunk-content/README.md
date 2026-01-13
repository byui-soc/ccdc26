# CCDC Splunk Content

Pre-built alerts and dashboards for CCDC competition monitoring.

## Directory Structure

```
splunk-content/
├── alerts/
│   └── ccdc-alerts.conf      # Saved searches/alerts
└── dashboards/
    ├── ccdc-security-overview.xml   # Main security dashboard
    ├── ccdc-authentication.xml      # Authentication monitoring
    ├── ccdc-network.xml             # Network monitoring
    ├── ccdc-web-servers.xml         # Web server monitoring
    └── ccdc-windows.xml             # Windows-specific monitoring
```

## Installation

### Alerts (Saved Searches)

**Option 1: Copy file directly**
```bash
cp alerts/ccdc-alerts.conf $SPLUNK_HOME/etc/apps/search/local/savedsearches.conf
# Restart Splunk
```

**Option 2: Import via Web UI**
1. Settings > Searches, reports, and alerts
2. Click "New Alert" and manually create using SPL from the file

### Dashboards

**Option 1: Copy files directly**
```bash
mkdir -p $SPLUNK_HOME/etc/apps/search/local/data/ui/views/
cp dashboards/*.xml $SPLUNK_HOME/etc/apps/search/local/data/ui/views/
# Restart Splunk
```

**Option 2: Import via Web UI**
1. Dashboards > Create New Dashboard
2. Click "Source" (top right)
3. Paste the XML content
4. Save

## Dashboards Overview

### Security Overview
Main dashboard showing:
- Active alerts count
- Failed/successful logins
- Hosts reporting
- Security events timeline
- Top attacking IPs
- User/account changes
- Persistence indicators
- CCDC toolkit findings

### Authentication Monitor
Detailed authentication analysis:
- Login statistics by host
- Authentication timeline (success vs failure)
- Source IP tracking
- Targeted usernames
- Sudo command history
- Windows logon types

### Network Monitor
Network connection tracking:
- Suspicious outbound connections
- Connections to known-bad ports
- New listening services
- Fail2ban activity
- Firewall events

### Web Server Monitor
Apache/Nginx/IIS monitoring:
- Request volume and errors
- Response code distribution
- Web shell access attempts
- SQL injection detection
- Directory traversal attempts
- Client IP tracking

### Windows Security
Windows Event Log analysis:
- Logon events by type
- Account changes
- PowerShell activity (including suspicious patterns)
- New services and scheduled tasks
- Sysmon process creation
- Windows Defender alerts
- RDP session tracking

## Alert Categories

### Critical (Severity 5)
- New user created
- User added to admin group
- Cron/systemd modifications
- SSH config changes
- Suspicious outbound connections
- Reverse shell port connections
- Web shell indicators
- Kernel module loading
- Log clearing

### High (Severity 4)
- Multiple failed logins (brute force)
- Password changes
- Sudoers modifications
- New listening ports
- Firewall rule changes
- SQL injection attempts
- Database auth failures

### Medium (Severity 3)
- Root/admin logins
- Logins from new IPs
- SSH outside business hours
- Web server error spikes
- Mail server auth failures
- Fail2ban bans

## Required Indexes

Create these indexes on your Splunk server:
- `main` - Default
- `security` - Auth, audit, intrusion prevention
- `os` - System logs
- `web` - Web server logs
- `database` - Database logs
- `mail` - Mail server logs
- `dns` - DNS server logs
- `ftp` - FTP server logs
- `ccdc` - CCDC toolkit output
- `wineventlog` - Windows event logs
- `containers` - Docker logs

## Customization

### Adjusting Alert Thresholds
Edit the alert SPL in `ccdc-alerts.conf`:
```
# Example: Change failed login threshold from 5 to 10
| where count > 10
```

### Adding Custom Alerts
Add new stanzas to `ccdc-alerts.conf`:
```
[CCDC - Custom Alert Name]
search = your SPL query here
dispatch.earliest_time = -5m
dispatch.latest_time = now
cron_schedule = */5 * * * *
enableSched = 1
alert.severity = 4
alert.track = 1
description = Description of what this alert detects
```

### Dashboard Refresh Rate
Modify `<refresh>` tags in dashboard XML:
```xml
<refresh>30s</refresh>  <!-- 30 seconds -->
<refresh>60s</refresh>  <!-- 1 minute -->
```
