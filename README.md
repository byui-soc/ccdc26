# CCDC26 Defense Toolkit

Script and info repo for 2026 CCDC season. Comprehensive toolkit for Linux and Windows system hardening, monitoring, and centralized logging with Splunk.

## Repository Structure

```
ccdc26/
├── linux-scripts/          # Linux defense toolkit
│   ├── hardening/          # System hardening scripts
│   ├── services/           # Service-specific hardening
│   ├── tools/              # Security tools & Splunk setup
│   ├── persistence-hunting/# Backdoor detection
│   ├── monitoring/         # Continuous monitoring
│   ├── incident-response/  # IR tools
│   └── utils/              # Shared utilities
├── windows-scripts/        # Windows defense toolkit
│   └── Install-SplunkForwarder.ps1
└── splunk-content/         # Splunk dashboards & alerts
    ├── alerts/             # Security alerts (saved searches)
    └── dashboards/         # Pre-built monitoring dashboards
```

## Quick Start

### 1. Set Up Splunk Server (First!)
```bash
# On your dedicated Splunk server
cd linux-scripts
sudo ./tools/splunk-server.sh
# Select option 1 for quick setup
# Note the admin password and server IP!
```

### 2. Deploy Linux Forwarders
```bash
# Edit the server IP first!
vim ./tools/splunk-forwarder.sh
# Set: SPLUNK_SERVER="your-splunk-ip"

# Then run on each Linux host
sudo ./tools/splunk-forwarder.sh
```

### 3. Deploy Windows Forwarders
```powershell
# Edit the server IP first!
# Set: $SPLUNK_SERVER = "your-splunk-ip"

# Run as Administrator
.\Install-SplunkForwarder.ps1
```

### 4. Import Splunk Content
```bash
# Copy alerts
cp splunk-content/alerts/ccdc-alerts.conf $SPLUNK_HOME/etc/apps/search/local/savedsearches.conf

# Copy dashboards
cp splunk-content/dashboards/*.xml $SPLUNK_HOME/etc/apps/search/local/data/ui/views/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

### 5. Harden Systems
```bash
# Linux
sudo ./hardening/full-harden.sh
sudo ./services/harden-all.sh
sudo ./tools/fail2ban-setup.sh

# Then start monitoring
sudo ./monitoring/deploy-monitoring.sh
```

## Splunk Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Linux Host 1   │     │  Linux Host 2   │     │  Windows Host   │
│  (UF + Toolkit) │     │  (UF + Toolkit) │     │  (UF + Events)  │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │ Port 9997
                                 ▼
                    ┌────────────────────────┐
                    │    Splunk Enterprise   │
                    │    (Free License)      │
                    │    ──────────────      │
                    │    Web UI: 8000        │
                    │    Dashboards          │
                    │    Alerts              │
                    └────────────────────────┘
```

## Log Sources Collected

### Linux (via linux-scripts/tools/splunk-forwarder.sh)
- Authentication: auth.log, secure, audit.log
- System: syslog, messages, kern.log, cron
- Web: Apache, Nginx (access + error logs)
- Database: MySQL, MariaDB, PostgreSQL
- Mail: Postfix, Dovecot
- DNS: BIND/named
- FTP: vsftpd, ProFTPD
- Security tools: fail2ban, rkhunter, ClamAV
- CCDC Toolkit: All monitoring output

### Windows (via windows-scripts/Install-SplunkForwarder.ps1)
- Security Event Log (4624, 4625, 4720, etc.)
- System Event Log
- PowerShell (Script Block Logging)
- Windows Defender
- Windows Firewall
- Sysmon (if installed)
- Task Scheduler
- Remote Desktop
- Active Directory (if DC)
- IIS Logs (if present)

## Dashboards Included

| Dashboard | Purpose |
|-----------|---------|
| Security Overview | Main SOC dashboard - alerts, logins, findings |
| Authentication | Login analysis, brute force detection, sudo tracking |
| Network | Connection monitoring, suspicious traffic, fail2ban |
| Web Servers | Apache/Nginx/IIS - attacks, errors, traffic |
| Windows Security | Event logs, PowerShell, services, Sysmon |

## Alert Coverage

**Critical Alerts:**
- New user/admin group changes
- Persistence mechanisms (cron, systemd, scheduled tasks)
- Web shells and SQL injection
- Suspicious PowerShell
- Log tampering

**High Alerts:**
- Brute force attacks
- SSH/firewall config changes
- Reverse shell indicators
- Database compromise attempts

**Medium Alerts:**
- Admin logins
- New IPs
- Fail2ban activity

## Competition Workflow

### First 15 Minutes
1. Deploy Splunk server
2. Deploy forwarders to all hosts
3. Import dashboards and alerts
4. Run `full-harden.sh` on Linux hosts

### Next 30 Minutes
5. Run service hardening
6. Set up fail2ban
7. Hunt for persistence
8. Start continuous monitoring

### Ongoing
- Monitor Splunk dashboards
- Respond to alerts
- Re-run persistence hunting periodically
- Document everything for scoring

## Free License Limits

Splunk Free License: **500 MB/day**

Tips to stay under limit:
- Disable verbose logging on quiet services
- Use `index=` to route logs appropriately
- Monitor `Settings > Licensing` in Splunk

## Team

- Brady Hodge (original toolkit)
- BYU-SOC Team (contributions)
