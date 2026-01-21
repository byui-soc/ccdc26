# CCDC26 Game Start Script - QUICK REFERENCE

**DROP FLAG: 9AM MST - January 24, 2026**

---

## ⏱️ TIMELINE

| Time | Priority | Action |
|------|----------|--------|
| **0:00-0:02** | 🔴 CRITICAL | Remove malware from ALL Linux machines |
| **0:02-0:05** | 🔴 CRITICAL | Change ALL passwords |
| **0:05-0:10** | 🟡 HIGH | Quick harden ALL machines |
| **0:10-0:15** | 🟢 MEDIUM | Deploy monitoring (Wazuh/Splunk) |
| **0:15+** | 🔵 ONGOING | Continuous monitoring + injects |

---

## 🚨 MINUTE 0-2: MALWARE REMOVAL (CRITICAL)

### Option A: Via Ansible (FASTEST)

**Run from Ubuntu Workstation (172.20.242.38):**

```bash
cd /opt/ccdc26
sudo ./deploy.sh
# Select: 2 (Ansible) → 8 (Run custom playbook)
# Enter: ansible/emergency-malware-removal.yml
```

### Option B: Manual (if Ansible not working)

**SSH to EACH Linux machine and run:**

```bash
sudo systemctl stop startup_check.service
sudo systemctl disable startup_check.service
sudo rm -f /etc/startup_check.py /etc/systemd/system/startup_check.service
sudo rm -f /usr/share/startup_check-installer.sh /etc/config.txt /var/log/startup_check.log
sudo find /home -name "authorized_keys" -delete
sudo find /root -name "authorized_keys" -delete
sudo systemctl daemon-reload
```

**Machines to clean:**
- ☐ Ubuntu Ecom (172.20.242.30)
- ☐ Fedora Webmail (172.20.242.40)
- ☐ Splunk (172.20.242.20)
- ☐ Ubuntu Workstation (172.20.242.38 or DHCP)

---

## 🔑 MINUTE 2-5: PASSWORD CHANGES

### Via Ansible

```bash
cd /opt/ccdc26
sudo ./deploy.sh
# Select: 2 (Ansible) → 3 (Password Reset + Kick Sessions)
# Enter your NEW team password when prompted
```

This will:
- Change password for ALL users on ALL machines
- Create ccdcuser1 and ccdcuser2 accounts
- Kill ALL active SSH sessions (boot attackers)

### Manual Windows Password Change

**If Ansible doesn't work for Windows, RDP to each Windows machine:**

```powershell
# Change administrator password
net user administrator "YourNewTeamP@ss!"

# Change other user passwords
net user userone "YourNewTeamP@ss!"
```

**Machines:**
- ☐ AD/DNS 2019 (172.20.240.102)
- ☐ Web 2019 (172.20.240.101)
- ☐ FTP 2022 (172.20.240.104)
- ☐ Win11 Workstation (172.20.240.100)

---

## 🛡️ MINUTE 5-10: QUICK HARDENING

### Linux via Ansible

```bash
cd /opt/ccdc26
sudo ./deploy.sh
# Select: 2 (Ansible) → 4 (Deploy Hardening) → 2 (Deploy and run)
```

### Windows Manual Hardening

**On EACH Windows machine, run as Administrator:**

```powershell
# Navigate to toolkit
cd C:\ccdc26\windows-scripts

# Harden any Windows machine
.\hardening\Full-Harden.ps1 -q

# On Domain Controller ONLY:
.\hardening\AD-Harden.ps1 -q
```

**Machines:**
- ☐ AD/DNS 2019 (run Full-Harden + AD-Harden)
- ☐ Web 2019 (run Full-Harden only)
- ☐ FTP 2022 (run Full-Harden only)
- ☐ Win11 Workstation (run Full-Harden only)

---

## 📡 MINUTE 10-15: MONITORING

### Deploy Wazuh Agents

```bash
cd /opt/ccdc26
sudo ./deploy.sh
# Select: 2 (Ansible) → 5 (Deploy Wazuh Agents)
# Enter Wazuh manager IP: 172.20.242.38 (if running on Ubuntu Wks)
```

### Deploy Splunk Forwarders (Backup)

```bash
cd /opt/ccdc26
sudo ./deploy.sh
# Select: 2 (Ansible) → 6 (Deploy Splunk Forwarders)
# Forwards to: 172.20.242.20
```

---

## 🔍 MINUTE 15+: CONTINUOUS MONITORING

### Every 10 Minutes

**Check for malware re-creation:**

```bash
# On each Linux machine:
systemctl status startup_check.service
ls -la /etc/startup_check.py /usr/share/startup_check-installer.sh

# Check UID 0 accounts:
awk -F: '$3 == 0 {print}' /etc/passwd

# Check for new SSH keys:
find /home /root -name "authorized_keys" -mmin -10
```

### Monitor Splunk Dashboard

- Access: https://172.20.242.20:8000
- Look for:
  - Failed login attempts
  - New processes
  - Outbound connections
  - File modifications in /etc, /usr/share

### Active Session Monitoring

```bash
# Check active SSH sessions
w

# Check established connections
ss -tulpn | grep ESTABLISHED

# Kill suspicious sessions
pkill -KILL -u suspicioususer
```

---

## 📋 PRE-FLIGHT CHECKLIST

**Before game starts, verify:**

- ☐ Ansible installed on Ubuntu Workstation: `ansible --version`
- ☐ sshpass installed: `which sshpass`
- ☐ pywinrm installed: `python3 -c "import winrm"`
- ☐ Toolkit cloned to /opt/ccdc26
- ☐ inventory.ini has correct IPs and passwords
- ☐ Ubuntu Workstation DHCP IP verified (update inventory if changed)
- ☐ WinRM enabled on ALL Windows machines (run Setup-WinRM-Ansible.ps1)
- ☐ Can ping all machines from Ubuntu Workstation
- ☐ Can SSH to all Linux machines
- ☐ Can RDP to all Windows machines

---

## 🆘 TROUBLESHOOTING

### Ansible Can't Connect

```bash
# Check sshpass installed
sudo apt install -y sshpass

# Disable host key checking
export ANSIBLE_HOST_KEY_CHECKING=False

# Test single machine
ansible ecom -i ansible/inventory.ini -m ping

# Check password in inventory.ini
cat ansible/inventory.ini | grep ansible_password
```

### Windows WinRM Not Working

**On Windows machine (as Administrator):**

```powershell
# Enable WinRM
winrm quickconfig -y

# Configure firewall
New-NetFirewallRule -Name "CCDC-WinRM" -DisplayName "WinRM CCDC" `
    -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5985 `
    -RemoteAddress 172.20.242.0/24 -Action Allow

# Test from Linux:
nc -zv 172.20.240.100 5985
```

### Malware Keeps Coming Back

**The malware runs every 10 minutes. If it reappears:**

1. Check for the config file: `cat /etc/config.txt`
2. Check for renamed installer: `ls -la /usr/share/*.sh`
3. Check for cron jobs: `crontab -l` and `crontab -e -u root`
4. Check systemd timers: `systemctl list-timers`
5. Look for other persistence: `cd /opt/ccdc26 && sudo ./deploy.sh` → 3 → 7 (Hunt for Persistence)

### Services Down After Hardening

**If scored services stop working:**

```bash
# Check service status
systemctl status apache2  # or httpd
systemctl status postfix
systemctl status dovecot

# Restart if needed
systemctl restart <service>

# Check firewall
sudo ufw status
# Allow scored service ports if blocked
```

---

## 🎯 SCORED SERVICES (DO NOT BREAK!)

| Service | Port | Server | Check |
|---------|------|--------|-------|
| HTTP | 80 | Ubuntu Ecom, Web 2019 | `curl http://IP` |
| HTTPS | 443 | Ubuntu Ecom, Web 2019 | `curl -k https://IP` |
| SMTP | 25 | Fedora Webmail | `nc -zv IP 25` |
| POP3 | 110 | Fedora Webmail | `nc -zv IP 110` |
| DNS | 53/udp | AD/DNS 2019 | `nslookup example.com IP` |

---

## 📞 TEAM ROLES

| Role | Responsibility | Location |
|------|---------------|----------|
| **Ansible Operator** | Run automation scripts | Ubuntu Wks (172.20.242.38) |
| **Linux Defender** | SSH to Linux machines, manual hardening | Any Linux box |
| **Windows Defender** | RDP to Windows machines, manual hardening | Win11 Wks (172.20.240.100) |
| **Network Monitor** | Watch Splunk, hunt threats | Ubuntu Wks or Splunk |
| **Inject Handler** | Respond to competition injects | Any machine |

---

## 🔗 QUICK LINKS

| Resource | URL/IP | Credentials |
|----------|--------|-------------|
| Splunk | https://172.20.242.20:8000 | admin / changemenow |
| Palo Alto Firewall | https://172.20.242.150 | admin / Changeme123 |
| Cisco FTD Firewall | https://172.20.240.200 | admin / !Changeme123 |
| NISE Portal | https://ccdcadmin1.morainevalley.edu | team02a - team02i |
| Stadium | https://ccdc.cit.morainevalley.edu | v2u1 - v2u8 |

---

## 📚 DOCUMENTATION

- **Full Pre-Game Checklist:** PRE-GAME-CHECKLIST.md
- **Quick Reference:** QUICKREF.md
- **Detailed README:** README.md
- **Ansible Inventory:** ansible/inventory.ini

---

## ✅ GAME START CHECKLIST

### T-minus 5 minutes:
- ☐ All team members in Discord voice
- ☐ Roles assigned
- ☐ Toolkit cloned and ready on Ubuntu Wks
- ☐ This script open and visible
- ☐ Terminal ready on Ubuntu Wks

### T-minus 0 (DROP FLAG):
- ☐ START TIMER
- ☐ Run malware removal (Minute 0-2)
- ☐ Change passwords (Minute 2-5)
- ☐ Quick harden (Minute 5-10)
- ☐ Deploy monitoring (Minute 10-15)
- ☐ Start continuous monitoring (Minute 15+)

---

**Good luck, Team 2! Stay calm, work fast, communicate clearly. You've got this! 🎯🔒**

---

**Last Updated:** January 21, 2026  
**Competition:** Rocky Mountain CCDC Qualifier 2026
