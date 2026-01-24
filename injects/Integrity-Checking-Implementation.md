# MEMORANDUM

| | |
|---|---|
| **TO:** | Management / IT Security Team |
| **FROM:** | Linux Systems Administration Team |
| **DATE:** | January 24, 2026 |
| **RE:** | File Integrity Checking Implementation |

---

## Executive Summary

This memo documents the deployment of file integrity monitoring across all Linux servers. The system monitors critical system files for unauthorized modifications and alerts administrators of any changes that may indicate compromise.

---

## Configuration Changes Made

### 1. Integrity Script Deployment

The file integrity monitoring script was deployed to each Linux server:

```bash
# Script location
/opt/ccdc-toolkit/linux-scripts/monitoring/file-monitor.sh

# Baseline storage location
/var/lib/ccdc-toolkit/baseline/
```

### 2. Startup Configuration (systemd Service)

Created a systemd service to run integrity checking at boot:

**File: `/etc/systemd/system/file-integrity.service`**
```ini
[Unit]
Description=File Integrity Monitor
After=network.target

[Service]
Type=simple
ExecStart=/opt/ccdc-toolkit/linux-scripts/monitoring/file-monitor.sh --check
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**Commands executed:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable file-integrity.service
sudo systemctl start file-integrity.service
```

### 3. Periodic Execution (Cron Configuration)

Added cron job for periodic integrity checking:

**File: `/etc/cron.d/file-integrity`**
```cron
# File Integrity Check - runs every 15 minutes
*/15 * * * * root /opt/ccdc-toolkit/linux-scripts/monitoring/file-monitor.sh --check >> /var/log/ccdc-toolkit/integrity-check.log 2>&1

# Daily baseline comparison report
0 6 * * * root /opt/ccdc-toolkit/linux-scripts/monitoring/file-monitor.sh --report >> /var/log/ccdc-toolkit/integrity-daily.log 2>&1
```

---

## Script Execution Frequency

| Check Type | Frequency | Purpose |
|------------|-----------|---------|
| Boot Check | On system startup | Verify integrity after reboot |
| Periodic Check | Every 15 minutes | Detect real-time modifications |
| Daily Report | 6:00 AM daily | Comprehensive daily summary |
| Continuous Monitor | Real-time (optional) | inotify-based live monitoring |

---

## Administrator Notification Methods

### 1. Log Files
All integrity violations are logged to:
- `/var/log/ccdc-toolkit/integrity-check.log` - Periodic check results
- `/var/log/ccdc-toolkit/file-changes.log` - Real-time change alerts
- `/var/log/ccdc-toolkit/findings.log` - Security findings

### 2. Splunk Integration
Logs are forwarded to Splunk server for centralized monitoring:
- Index: `linux-security`
- Sourcetype: `file_integrity`

### 3. Console Alerts
Critical changes trigger immediate console output with color-coded alerts:
- **RED [ALERT]** - File modification detected
- **YELLOW [WARN]** - Permission changes detected

### 4. Email Notification (Optional)
Configure in `/etc/ccdc-toolkit/notify.conf`:
```bash
ADMIN_EMAIL="admin@company.local"
NOTIFY_ON_CHANGE=true
```

---

## Monitored Directories and Files

### Critical System Files

| File | Why Important |
|------|---------------|
| `/etc/passwd` | User account definitions - modifications could add rogue users |
| `/etc/shadow` | Password hashes - tampering enables unauthorized access |
| `/etc/group` | Group memberships - changes could escalate privileges |
| `/etc/sudoers` | Sudo privileges - modifications grant root access |
| `/etc/ssh/sshd_config` | SSH configuration - could enable insecure access |
| `/etc/hosts` | DNS overrides - could redirect traffic to malicious servers |
| `/etc/crontab` | Scheduled tasks - attacker persistence mechanism |
| `/etc/profile` | Login scripts - code execution on every login |
| `/etc/bashrc` | Shell config - code execution on every shell |
| `/etc/ld.so.preload` | Library preloading - rootkit injection point |
| `/root/.ssh/authorized_keys` | SSH keys - unauthorized remote access |
| `/root/.bashrc` | Root shell config - privileged code execution |

### Critical Directories

| Directory | Why Important |
|-----------|---------------|
| `/etc/cron.d/` | Cron jobs - persistence mechanism for attackers |
| `/etc/cron.daily/` | Daily scheduled tasks - hidden malware execution |
| `/etc/cron.hourly/` | Hourly tasks - frequent malware callbacks |
| `/etc/sudoers.d/` | Additional sudo rules - privilege escalation |
| `/etc/systemd/system/` | Custom services - persistence via services |
| `/etc/profile.d/` | Login scripts - user session compromise |
| `/etc/pam.d/` | Authentication modules - backdoor authentication |

---

## Proof of Implementation

### Server 1: <!-- HOSTNAME -->

**Screenshot: systemd service status**
<!-- INSERT SCREENSHOT: systemctl status file-integrity.service -->

**Screenshot: cron configuration**
<!-- INSERT SCREENSHOT: cat /etc/cron.d/file-integrity -->

**Screenshot: baseline created**
<!-- INSERT SCREENSHOT: ls -la /var/lib/ccdc-toolkit/baseline/ -->

**Screenshot: integrity check output**
<!-- INSERT SCREENSHOT: ./file-monitor.sh check output -->

---

### Server 2: <!-- HOSTNAME -->

**Screenshot: systemd service status**
<!-- INSERT SCREENSHOT -->

**Screenshot: cron configuration**
<!-- INSERT SCREENSHOT -->

**Screenshot: integrity check output**
<!-- INSERT SCREENSHOT -->

---

### Server 3: <!-- HOSTNAME -->

**Screenshot: systemd service status**
<!-- INSERT SCREENSHOT -->

**Screenshot: cron configuration**
<!-- INSERT SCREENSHOT -->

**Screenshot: integrity check output**
<!-- INSERT SCREENSHOT -->

---

## Quick Deployment Commands

For each Linux server, run:

```bash
# 1. Create baseline
sudo /opt/ccdc-toolkit/linux-scripts/monitoring/file-monitor.sh
# Select option 1

# 2. Create systemd service
sudo tee /etc/systemd/system/file-integrity.service << 'EOF'
[Unit]
Description=File Integrity Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ccdc-toolkit/linux-scripts/monitoring/file-monitor.sh --check

[Install]
WantedBy=multi-user.target
EOF

# 3. Create cron job
echo '*/15 * * * * root /opt/ccdc-toolkit/linux-scripts/monitoring/file-monitor.sh --check >> /var/log/ccdc-toolkit/integrity.log 2>&1' | sudo tee /etc/cron.d/file-integrity

# 4. Enable and start
sudo systemctl daemon-reload
sudo systemctl enable file-integrity.service

# 5. Verify
sudo systemctl status file-integrity.service
cat /etc/cron.d/file-integrity
```

---

*Implementation completed by Linux Systems Administration Team*
