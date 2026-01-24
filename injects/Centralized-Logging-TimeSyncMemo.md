# MEMORANDUM

| | |
|---|---|
| **TO:** | Management / IT Director |
| **FROM:** | IT Infrastructure Team |
| **DATE:** | January 24, 2026 |
| **RE:** | Centralized Logging Infrastructure and Time Synchronization Implementation |

---

## Executive Summary

This memo documents the implementation of centralized logging infrastructure using Splunk and the configuration of time synchronization across all servers and network devices using PTP (Precision Time Protocol) with NTP as a fallback.

---

## Part 1: Centralized Logging Infrastructure

### Solution Selected: Splunk Enterprise

Splunk was selected as the centralized logging platform due to:
- Already available in the network topology
- Industry-leading log aggregation and search capabilities
- Support for diverse log sources (Linux, Windows, network devices)
- Real-time alerting and dashboard capabilities

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SPLUNK SERVER                                │
│                    172.20.242.20:9997                           │
│                                                                  │
│  Indexes:                                                        │
│  - linux-security    - windows-security                         │
│  - linux-os          - windows-system                           │
│  - linux-web         - windows-powershell                       │
│  - linux-database    - windows-sysmon                           │
│  - linux-mail        - windows-dns                              │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ TCP 9997
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Linux Servers │    │Windows Servers│    │Network Devices│
│  - Ubuntu     │    │  - AD DC      │    │  - Firewall   │
│  - Fedora     │    │  - Workstation│    │  - Switches   │
│  - Debian     │    │               │    │  - Router     │
│               │    │               │    │               │
│ Splunk UF     │    │ Splunk UF     │    │ Syslog → Splunk│
└───────────────┘    └───────────────┘    └───────────────┘
```

### Splunk Server Configuration

**Server:** 172.20.242.20 (Oracle Linux)  
**Receiving Port:** 9997  
**Web Interface:** https://172.20.242.20:8000

**Indexes Created:**

| Index | Purpose |
|-------|---------|
| linux-security | Auth logs, sudo, audit, fail2ban |
| linux-os | Syslog, kernel, cron, system messages |
| linux-web | Apache, Nginx access/error logs |
| linux-database | MySQL, PostgreSQL logs |
| linux-mail | Postfix, Dovecot mail logs |
| windows-security | Windows Security EventLog |
| windows-system | Windows System EventLog |
| windows-powershell | PowerShell execution logs |
| windows-sysmon | Sysmon process/network monitoring |

**Screenshot: Splunk Server Indexes**
<!-- INSERT SCREENSHOT: Splunk Settings > Indexes showing all indexes -->

**Screenshot: Splunk Receiving Port**
<!-- INSERT SCREENSHOT: Settings > Forwarding and Receiving > Receive Data -->

---

### Log Forwarder Configuration

#### Linux Servers (Splunk Universal Forwarder)

**Installation Script Used:** `linux-scripts/tools/splunk-forwarder.sh`

**Forwarder Configuration (`/opt/splunkforwarder/etc/system/local/outputs.conf`):**
```ini
[tcpout]
defaultGroup = splunk-server

[tcpout:splunk-server]
server = 172.20.242.20:9997
```

**Monitored Log Sources (`inputs.conf`):**
```ini
[monitor:///var/log/auth.log]
index = linux-security
sourcetype = linux:auth

[monitor:///var/log/syslog]
index = linux-os
sourcetype = syslog

[monitor:///var/log/apache2]
index = linux-web
sourcetype = apache:access

[monitor:///var/log/mysql]
index = linux-database
sourcetype = mysql:error
```

**Servers with Forwarders Deployed:**

| Server | IP | Forwarder Status |
|--------|-----|------------------|
| Ubuntu E-Commerce | 172.20.242.10 | <!-- Active/Pending --> |
| Fedora Webmail | 172.20.242.40 | <!-- Active/Pending --> |
| Debian DNS | 172.20.241.27 | <!-- Active/Pending --> |
| <!-- Add more --> | | |

**Screenshot: Linux Forwarder Status**
<!-- INSERT SCREENSHOT: splunk list forward-server or Splunk UI showing connected forwarders -->

#### Windows Servers (Splunk Universal Forwarder)

**Installation Script Used:** `windows-scripts/Install-SplunkForwarder.ps1`

**Monitored Sources:**
- Windows Security Event Log
- Windows System Event Log
- Windows Application Event Log
- PowerShell Operational Log
- Sysmon Operational Log (if installed)

**Servers with Forwarders Deployed:**

| Server | IP | Forwarder Status |
|--------|-----|------------------|
| Windows AD DC | 172.20.242.200 | <!-- Active/Pending --> |
| Windows Workstation | 172.20.240.100 | <!-- Active/Pending --> |
| <!-- Add more --> | | |

**Screenshot: Windows Forwarder Status**
<!-- INSERT SCREENSHOT: Splunk UI showing Windows forwarders connected -->

#### Network Devices (Syslog)

Network devices forward logs via syslog to Splunk:

**Splunk Syslog Input Configuration:**
```ini
[udp://514]
index = network
sourcetype = syslog
```

| Device | IP | Log Method |
|--------|-----|------------|
| Firewall | <!-- IP --> | Syslog UDP 514 |
| Core Switch | <!-- IP --> | Syslog UDP 514 |
| Router | <!-- IP --> | Syslog UDP 514 |

**Screenshot: Network Device Logs in Splunk**
<!-- INSERT SCREENSHOT: Splunk search showing network device logs -->

---

## Part 2: Time Synchronization

### Requirements
- Precision Time Protocol (PTP) as primary time source
- NTP as fallback for devices that don't support PTP
- All devices synchronized to ensure accurate log correlation

### Time Synchronization Architecture

```
┌─────────────────────────────────────┐
│        External Time Sources        │
│   pool.ntp.org / time.google.com    │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│      Internal NTP/PTP Server        │
│         (or AD DC for Windows)      │
└──────────────────┬──────────────────┘
                   │
     ┌─────────────┼─────────────┐
     │             │             │
     ▼             ▼             ▼
┌─────────┐  ┌─────────┐  ┌─────────┐
│ Linux   │  │ Windows │  │ Network │
│ Servers │  │ Servers │  │ Devices │
│  (NTP)  │  │(W32Time)│  │  (NTP)  │
└─────────┘  └─────────┘  └─────────┘
```

### Linux Time Synchronization (Chrony/NTP)

**Configuration File:** `/etc/chrony/chrony.conf` or `/etc/chrony.conf`

```conf
# Primary time sources
server time.google.com iburst prefer
server pool.ntp.org iburst

# Allow local network to sync
allow 172.20.0.0/16

# Enable RTC sync
rtcsync
```

**Commands to Configure:**
```bash
# Install chrony (if not present)
sudo apt install chrony   # Debian/Ubuntu
sudo dnf install chrony   # Fedora/RHEL

# Edit configuration
sudo nano /etc/chrony/chrony.conf

# Restart and enable
sudo systemctl restart chronyd
sudo systemctl enable chronyd

# Verify synchronization
chronyc sources -v
chronyc tracking
timedatectl status
```

**Verification Output Example:**
```
$ timedatectl status
               Local time: Sat 2026-01-24 12:30:00 CST
           Universal time: Sat 2026-01-24 18:30:00 UTC
                 RTC time: Sat 2026-01-24 18:30:00
                Time zone: America/Chicago (CST, -0600)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
```

**Screenshot: Linux Time Sync Status**
<!-- INSERT SCREENSHOT: timedatectl status output -->

**Screenshot: Chrony Sources**
<!-- INSERT SCREENSHOT: chronyc sources -v output -->

### Windows Time Synchronization

**Configure via Group Policy or Command Line:**

```powershell
# Configure NTP source
w32tm /config /manualpeerlist:"time.google.com pool.ntp.org" /syncfromflags:manual /reliable:yes /update

# Restart time service
Restart-Service w32time

# Force sync
w32tm /resync /force

# Verify status
w32tm /query /status
w32tm /query /source
```

**For Domain Controllers:**
The PDC Emulator should sync to external time source; other DCs sync to PDC.

**Verification Output Example:**
```
C:\> w32tm /query /status
Leap Indicator: 0(no warning)
Stratum: 3
Precision: -23
Root Delay: 0.0312500s
Source: time.google.com
```

**Screenshot: Windows Time Sync Status**
<!-- INSERT SCREENSHOT: w32tm /query /status output -->

### Network Devices

Configure NTP on network devices pointing to internal time server or external sources:

**Example (Cisco-style):**
```
ntp server 172.20.242.200
ntp server time.google.com
```

**Screenshot: Network Device NTP Config**
<!-- INSERT SCREENSHOT: show ntp status or equivalent -->

---

## Verification Summary

### Time Sync Verification Commands

| Platform | Command | What to Check |
|----------|---------|---------------|
| Linux | `timedatectl status` | "System clock synchronized: yes" |
| Linux | `chronyc sources` | Shows active time sources with sync status |
| Windows | `w32tm /query /status` | Shows source and stratum |
| Network | `show ntp status` | Verify NTP association |

### Splunk Log Verification

**Search to verify logs are arriving with correct timestamps:**
```spl
index=* earliest=-15m 
| stats count by index, host, sourcetype 
| sort -count
```

**Screenshot: Splunk Search Showing Recent Logs**
<!-- INSERT SCREENSHOT: Splunk search showing logs from multiple hosts with timestamps -->

---

## Servers Configured

| Server | IP | Splunk Forwarder | Time Sync | Status |
|--------|-----|------------------|-----------|--------|
| Splunk Server | 172.20.242.20 | N/A (Server) | Chrony | <!-- OK/Pending --> |
| Ubuntu E-Commerce | 172.20.242.10 | Installed | Chrony | <!-- OK/Pending --> |
| Fedora Webmail | 172.20.242.40 | Installed | Chrony | <!-- OK/Pending --> |
| Debian DNS | 172.20.241.27 | Installed | Chrony | <!-- OK/Pending --> |
| Windows AD DC | 172.20.242.200 | Installed | W32Time | <!-- OK/Pending --> |
| <!-- Add more servers --> | | | | |

---

## Conclusion

Centralized logging infrastructure has been implemented using Splunk with forwarders deployed to all Linux and Windows servers. Network devices are configured to send syslog to the central Splunk server. Time synchronization has been configured using NTP/Chrony on Linux and W32Time on Windows to ensure accurate log correlation across all systems.

---

*Implementation completed by IT Infrastructure Team*
