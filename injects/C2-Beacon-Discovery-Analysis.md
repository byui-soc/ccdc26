# MEMORANDUM

| | |
|---|---|
| **TO:** | Management / Security Team |
| **FROM:** | Incident Response Team |
| **DATE:** | January 24, 2026 |
| **RE:** | Command and Control (C2) Beacon Discovery and Remediation |

---

## Executive Summary

Following notification from our Internet Service Provider about potential C2 beaconing activity, our team conducted an investigation using packet capture and firewall analysis. **A C2 beacon was identified and successfully removed.** This memo documents the discovery process, analysis of the malicious traffic, and remediation steps taken.

---

## Discovery Steps

### Step 1: Network Traffic Analysis

We utilized packet capture tools to monitor outbound network traffic for periodic connection patterns indicative of C2 beaconing.

**Tools Used:**
- tcpdump / Wireshark for packet capture
- Firewall logs (Palo Alto)
- Splunk for log correlation

**Commands Executed:**
```bash
# Capture outbound traffic
sudo tcpdump -i eth0 -w /tmp/capture.pcap -c 10000

# Monitor for periodic connections
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' -n

# Check for established outbound connections
ss -tnp | grep ESTAB
netstat -tnp | grep ESTAB
```

### Step 2: Firewall Log Analysis

Reviewed firewall deny logs for blocked outbound connection attempts:

```
# Palo Alto
show log traffic direction eq backward action eq deny

# Or via Splunk
index=firewall action=denied direction=outbound
| stats count by src_ip, dest_ip, dest_port
| where count > 10
```

### Step 3: Process Investigation

Identified suspicious processes making network connections:

```bash
# Find processes with network connections
lsof -i -P -n | grep ESTABLISHED
ss -tnp

# Check for periodic scheduled tasks
crontab -l
ls -la /etc/cron.d/
systemctl list-timers
```

---

## Packet Capture Evidence

### Screenshot: C2 Beacon Traffic

![Packet Capture showing SSH beacon traffic with paramiko](./screenshots/c2-beacon-capture.png)

**Key evidence visible in capture:**
- `SSH-2.0-paramiko_2.12.0` - Identifies the Python Paramiko SSH library used by malware
- `SSH-2.0-OpenSSH_8.0` - Target systems responding to connection attempts

### Beacon Characteristics Observed

| Attribute | Value | Suspicious Indicator |
|-----------|-------|---------------------|
| Source IP | **172.20.242.30** (port 60858, 33614) | Ubuntu Ecom - Infected server |
| Destination IP #1 | **172.20.242.102:22** | Internal target - SSH lateral movement |
| Destination IP #2 | **172.20.242.254:22** | Palo Alto Firewall - Critical infrastructure target |
| Protocol | TCP/SSH (port 22) | Used for remote command execution |
| SSH Client | **SSH-2.0-paramiko_2.12.0** | Python library - NOT normal user SSH client |
| Frequency | Every 10 minutes (600 seconds) | Regular beaconing interval |
| Behavior | SYN → SYN-ACK → Data transfer | Full SSH session establishment |

### Why `SSH-2.0-paramiko_2.12.0` Is Suspicious

Normal SSH connections show client strings like:
- `SSH-2.0-OpenSSH_8.x` (Linux/Mac users)
- `SSH-2.0-PuTTY_Release_0.x` (Windows users)

The presence of `paramiko` indicates:
- **Automated/scripted SSH connection** (not human user)
- **Python-based tooling** (common in attack frameworks)
- **Programmatic access** designed for remote command execution

---

## Why This Traffic Is Suspicious

### Beaconing Indicators

1. **Periodic Timing Pattern**
   - Connections occur at regular 10-minute intervals
   - Consistent with automated C2 check-in behavior
   - Not characteristic of normal user or application traffic

2. **SSH to Multiple Internal Hosts**
   - Malware was SSHing to internal systems (172.20.242.x)
   - Using root credentials
   - Attempting lateral movement

3. **Automated Execution**
   - No user interaction required
   - Running as system daemon
   - Persists across reboots

4. **Script Deployment**
   - Copies and executes scripts on remote systems
   - Self-propagating worm behavior
   - Indicates intent to spread

### Suspicious Elements in Packet Analysis

| Element | Why Suspicious |
|---------|----------------|
| Regular interval (600s) | Classic C2 beacon timing |
| SSH protocol for automation | Enables remote command execution |
| Root authentication | Maximum privilege access |
| Connection to multiple targets | Lateral movement pattern |
| Payload transfer (SFTP) | Deploying additional malware |

---

## Data Exfiltration Assessment

### Was Data Being Exfiltrated?

**Assessment: LOW PROBABILITY of data exfiltration, HIGH PROBABILITY of propagation**

**Evidence:**

1. **Primary Function Was Propagation**
   - Code analysis shows the malware's purpose was spreading to other systems
   - Copied installer scripts to remote hosts
   - No evidence of data collection or upload functions

2. **No External C2 Server**
   - Beaconing was to INTERNAL addresses (172.20.242.x)
   - Not communicating with external attacker infrastructure
   - Designed for internal network compromise

3. **Traffic Pattern Analysis**
   - Outbound data volume was minimal (script files only)
   - No large data transfers observed
   - No connections to external IP addresses

**However:**
- The malware COULD be a first-stage loader for future exfiltration
- Attacker may have been establishing foothold before data theft
- Other malware components may exist that we haven't discovered

---

## Affected Server

### Compromised System Details

| Attribute | Value |
|-----------|-------|
| **Hostname** | czatelif (Ubuntu Ecom) |
| **IP Address** | 172.20.242.30 |
| **Operating System** | Ubuntu Server 24.04.3 |
| **Role** | E-Commerce Server |
| **Infection Date** | December 15, 2025 (based on file timestamps) |
| **Discovery Date** | January 24, 2026 |

### Additional Targeted Systems

| IP Address | System | Status |
|------------|--------|--------|
| 172.20.242.102 | Unknown | Checked - Clean |
| 172.20.242.254 | Palo Alto Firewall | Verified Clean |

---

## Removal Steps Taken

### Immediate Containment

```bash
# 1. Killed the malicious process
sudo kill -9 752   # PID of startup_check.py

# 2. Verified process termination
ps aux | grep startup_check
```

### Malware Removal

```bash
# 3. Removed all malware components
sudo rm -f /etc/startup_check.py          # Main malware daemon
sudo rm -f /etc/config.txt                # Target/credential list
sudo rm -f /usr/share/startup_check-installer.sh  # Propagation script
sudo rm -f /var/log/startup_check.log     # Malware log
sudo rm -f ~/install-ssh-req.sh           # Dependency installer

# 4. Removed malware dependencies
sudo pip3 uninstall -y paramiko
```

### Persistence Removal

```bash
# 5. Disabled and removed systemd service
sudo systemctl stop startup-check 2>/dev/null
sudo systemctl disable startup-check 2>/dev/null
sudo rm -f /etc/systemd/system/startup*.service
sudo systemctl daemon-reload

# 6. Checked and cleaned cron
crontab -l | grep -v startup_check | crontab -
sudo rm -f /etc/cron.d/*startup*
```

### Credential Remediation

```bash
# 7. Audited SSH authorized_keys
sudo cat /root/.ssh/authorized_keys
# Removed any unrecognized keys

# 8. Changed passwords
passwd root
passwd sysadmin
```

---

## Assurance: Preventing Persistence

### Verification Steps Completed

| Check | Result |
|-------|--------|
| Process running? | **NO** - Verified with `ps aux` |
| Malware files exist? | **NO** - All files removed |
| Systemd service? | **NO** - Service deleted |
| Cron entries? | **NO** - Cron cleaned |
| Paramiko installed? | **NO** - Package removed |
| SSH keys compromised? | **NO** - Keys audited |

### Ongoing Protection Measures

1. **File Integrity Monitoring**
   - Deployed integrity-baseline.sh and integrity-monitor.sh
   - Monitoring /etc/ for unauthorized changes
   - Alerts via SYSLOG every 5 minutes

2. **Network Monitoring**
   - Firewall deny-any rule with logging enabled
   - Splunk monitoring for SSH anomalies
   - Alert on new outbound connections

3. **Access Controls**
   - Passwords changed on all affected systems
   - SSH keys audited and cleaned
   - Root SSH login restricted where possible

4. **Endpoint Hardening**
   - Removed unnecessary Python packages
   - Restricted pip install permissions
   - Enabled additional logging

---

## Management Assurance

We can confirm that:

1. **The C2 beacon has been eliminated** - The malicious process has been terminated and all associated files removed

2. **Persistence mechanisms have been disabled** - Systemd services and cron entries removed

3. **The malware cannot restart** - Dependencies (paramiko) uninstalled, source files deleted

4. **Network-wide verification completed** - All Linux systems checked and cleaned

5. **Monitoring is in place** - File integrity and network monitoring will detect any recurrence

6. **Credentials have been rotated** - Compromised passwords and SSH keys replaced

---

## Recommendations

1. Continue monitoring firewall logs for unusual outbound patterns
2. Implement network segmentation to limit lateral movement
3. Deploy EDR solution for enhanced endpoint visibility
4. Conduct regular vulnerability assessments
5. Review and harden SSH configurations across all systems

---

*Report prepared by Incident Response Team - January 24, 2026*
