# RMCCDC 2026 Qualifier - Competition Day Cheat Sheet

**Date:** January 24, 2026  
**Time:** 8am-4pm MST (9am Drop Flag)  
**Team Number:** 2 (BYU)  
**Public IP Range:** 172.25.22.0/24

> **NOTE:** Ubuntu Workstation has DHCP! Get its actual IP after drop flag before deploying Wazuh.

---

## SCRIPT SAFETY FEATURES (Auto-Enabled)

The hardening scripts have been updated with CCDC-safe defaults:

| Feature | What It Does |
|---------|--------------|
| **Auto-detect services** | Firewall scripts detect running web/mail/DNS and auto-allow their ports |
| **Web servers protected** | Apache, Nginx, httpd are NOT in the "dangerous services" list |
| **Mail servers protected** | Postfix/Dovecot allow competition networks (172.x.x.x) for scoring |
| **Print Spooler safe** | Windows PrintNightmare fix does NOT disable spooler (for injects) |
| **SSH team-friendly** | MaxSessions=10 (was 3) for 8-person team access |
| **Wazuh auto-detect** | Agent tries to find manager on 172.20.242.x range |

**The scripts will PROMPT before applying firewall rules** - verify the detected ports are correct!

---

## CRITICAL FIRST ACTIONS (Before 9am Drop Flag)

```
1. Login to NISE: https://ccdcadmin1.morainevalley.edu
   - Accounts: team02a, team02b, team02c, team02d, team02e, team02f, team02g, team02h, team02i
   - (Password will be provided by competition manager)
   - Respond to "Welcome" inject immediately

2. Complete survey part 1 (required inject)

3. Wait for Drop Flag notification at 9am MST

4. Competition Stadium: https://ccdc.cit.morainevalley.edu
   - Accounts: v2u1, v2u2, v2u3, v2u4, v2u5, v2u6, v2u7, v2u8
```

---

## SYSTEM CREDENTIALS (CHANGE THESE IMMEDIATELY!)

### Linux Systems

| System | IP | Username | Default Password | Services |
|--------|-----|----------|------------------|----------|
| **Ubuntu Ecom** | 172.20.242.30 | sysadmin | changeme | HTTP, HTTPS (scored) |
| **Fedora Webmail** | 172.20.242.40 | sysadmin | changeme | SMTP, POP3 (scored) |
| **Splunk/Oracle** | 172.20.242.20 | root | changemenow | Splunk Web |
| | | sysadmin | changemenow | |
| | | admin | changeme | (Splunk Web UI) |
| **Ubuntu Wks** | DHCP | sysadmin | changeme | Workstation |
| **VyOS Router** | 172.16.101.1 | vyos | changeme | Routing |

### Windows Systems

| System | IP | Username | Default Password | Services |
|--------|-----|----------|------------------|----------|
| **AD/DNS 2019** | 172.20.240.102 | administrator | !Password123 | DNS (scored), AD |
| **Web 2019** | 172.20.240.101 | administrator | !Password123 | HTTP, HTTPS (scored) |
| **FTP 2022** | 172.20.240.104 | administrator | !Password123 | FTP |
| **Win11 Wks** | 172.20.240.100 | administrator | !Password123 | Workstation |
| | | UserOne | ChangeMe123 | |

### Network Devices

| Device | Management IP | Access From | Username | Default Password |
|--------|--------------|-------------|----------|------------------|
| **Palo Alto** | 172.20.242.150 | Ubuntu Wks browser | admin | Changeme123 |
| **Cisco FTD** | 172.20.240.200 | Win11 Wks browser | admin | !Changeme123 |
| | 172.20.102.254 | (alternate) | | |

---

## NETWORK TOPOLOGY (TEAM 2)

```
                            INTERNET/SCORING
                                  │
                    ┌─────────────┴─────────────┐
                    │       VyOS Router         │
                    │  external: 172.31.22.2/29 │  ← Team 2
                    │  net1: 172.16.101.1/24    │
                    │  net2: 172.16.102.1/24    │
                    └──────┬──────────┬─────────┘
                           │          │
          ┌────────────────┘          └────────────────┐
          │                                            │
          ▼                                            ▼
┌─────────────────────┐                    ┌─────────────────────┐
│    Palo Alto FW     │                    │    Cisco FTD FW     │
│ outside: 172.16.101.254                  │ outside: 172.16.102.254
│ inside:  172.20.242.254                  │ inside:  172.20.240.254
│ mgmt:    172.20.242.150                  │ mgmt:    172.20.240.200
└─────────┬───────────┘                    └─────────┬───────────┘
          │                                          │
          │ 172.20.242.0/24                         │ 172.20.240.0/24
          │ (Linux Zone)                            │ (Windows Zone)
          │                                          │
    ┌─────┼─────────────────┐                  ┌─────┴─────┐
    │     │                 │                  │           │
┌───┴───┐ │ ┌───────┐ ┌─────┴─────┐      ┌─────┴─────┐ ┌───┴───┐
│Ubuntu │ │ │Fedora │ │  Ubuntu   │      │  AD/DNS   │ │  Web  │
│ Ecom  │ │ │Webmail│ │   Wks     │      │  2019     │ │ 2019  │
│.30    │ │ │.40    │ │  (DHCP)   │      │  .102     │ │ .101  │
└───────┘ │ └───────┘ └───────────┘      └───────────┘ └───────┘
          │                                    │
    ┌─────┴─────┐                    ┌─────────┼─────────┐
    │  Splunk   │                    │         │         │
    │  .20      │              ┌─────┴───┐ ┌───┴───┐ ┌───┴───┐
    └───────────┘              │   FTP   │ │ Win11 │ │       │
                               │  2022   │ │  Wks  │ │       │
                               │  .104   │ │ .100  │ │       │
                               └─────────┘ └───────┘ └───────┘
```

---

## PUBLIC IP ADDRESSES (by team)

Your public IPs = **172.25.(20+team#).XXX**

| Team | Public IP Range | Router Outbound | Core Connection |
|------|-----------------|-----------------|-----------------|
| 1 | 172.25.21.0/24 | 172.31.21.2/29 | 172.31.21.1 |
| 2 | 172.25.22.0/24 | 172.31.22.2/29 | 172.31.22.1 |
| 3 | 172.25.23.0/24 | 172.31.23.2/29 | 172.31.23.1 |
| 4 | 172.25.24.0/24 | 172.31.24.2/29 | 172.31.24.1 |
| 5 | 172.25.25.0/24 | 172.31.25.2/29 | 172.31.25.1 |
| 6 | 172.25.26.0/24 | 172.31.26.2/29 | 172.31.26.1 |
| 7 | 172.25.27.0/24 | 172.31.27.2/29 | 172.31.27.1 |
| 8 | 172.25.28.0/24 | 172.31.28.2/29 | 172.31.28.1 |
| 9 | 172.25.29.0/24 | 172.31.29.2/29 | 172.31.29.1 |
| 10 | 172.25.30.0/24 | 172.31.30.2/29 | 172.31.30.1 |

**TEAM 2 Public IP Mapping:**

| Service | Internal IP | Public IP (Team 2) |
|---------|-------------|-------------------|
| Ubuntu Ecom | 172.20.242.30 | **172.25.22.11** |
| Fedora Webmail | 172.20.242.40 | **172.25.22.39** |
| Splunk | 172.20.242.20 | **172.25.22.9** |
| AD/DNS | 172.20.240.102 | **172.25.22.155** |
| Web 2019 | 172.20.240.101 | **172.25.22.140** |
| FTP 2022 | 172.20.240.104 | **172.25.22.162** |
| Win11 Wks | 172.20.240.100 | **172.25.22.144** |

---

## SCORED SERVICES

| Service | Protocol | Server | What's Checked |
|---------|----------|--------|----------------|
| **HTTP** | TCP/80 | Ubuntu Ecom, Web 2019 | Specific page content must match |
| **HTTPS** | TCP/443 | Ubuntu Ecom, Web 2019 | Page over SSL, content must match |
| **SMTP** | TCP/25 | Fedora Webmail | Email send/receive functionality |
| **POP3** | TCP/110 | Fedora Webmail | Login and retrieve email |
| **DNS** | UDP/53 | AD/DNS 2019 | DNS lookups must resolve |

**CRITICAL:** Do NOT change IP addresses or move services to different IPs!

---

## MACHINE STARTUP CHECKLISTS (Prerequisites by OS)

Before you can download and run the toolkit, each machine needs certain packages installed.

### Fedora (Webmail - 172.20.242.40)
```bash
# Install prerequisites
sudo dnf install -y git curl wget

# If this is your Ansible controller, also run:
sudo dnf install -y python3-pip
pip3 install ansible pywinrm

# Clone and run
git clone https://github.com/YOUR_REPO/ccdc26.git /opt/ccdc26
cd /opt/ccdc26
sudo bash deploy.sh
```

### Ubuntu (Ecom - 172.20.242.30, Workstation - DHCP)
```bash
# Install prerequisites
sudo apt update
sudo apt install -y git curl wget

# If this is your Ansible controller, also run:
sudo apt install -y python3-pip
pip3 install ansible pywinrm

# Clone and run
git clone https://github.com/YOUR_REPO/ccdc26.git /opt/ccdc26
cd /opt/ccdc26
sudo bash deploy.sh
```

### Oracle Linux (Splunk - 172.20.242.20)
```bash
# Install prerequisites
sudo dnf install -y git curl wget

# If this is your Ansible controller, also run:
sudo dnf install -y python3-pip
pip3 install ansible pywinrm

# Clone and run
git clone https://github.com/YOUR_REPO/ccdc26.git /opt/ccdc26
cd /opt/ccdc26
sudo bash deploy.sh
```

### Windows Server 2019/2022 & Windows 11
```powershell
# Option 1: If git is available
git clone https://github.com/YOUR_REPO/ccdc26.git C:\ccdc26

# Option 2: Download ZIP from GitHub
Invoke-WebRequest -Uri "https://github.com/YOUR_REPO/ccdc26/archive/main.zip" -OutFile C:\ccdc26.zip
Expand-Archive C:\ccdc26.zip -DestinationPath C:\
Rename-Item C:\ccdc26-main C:\ccdc26


# Run hardening
cd C:\ccdc26\windows-scripts\hardening
.\Full-Harden.ps1 -q

# On Domain Controller only:
.\AD-Harden.ps1 -q
```

### VyOS Router (172.16.101.1)
```bash
# VyOS is read-only filesystem - can't install packages
# Copy scripts manually or run commands from cheatsheet
# Focus on: password change, firewall rules, logging
configure
set system login user vyos authentication plaintext-password 'NewSecureP@ss!'
commit
save
```

### Quick Reference Table

| Machine | OS | Package Manager | Prerequisites Command |
|---------|----|-----------------|-----------------------|
| Fedora Webmail | Fedora | dnf | `sudo dnf install -y git curl` |
| Ubuntu Ecom | Ubuntu | apt | `sudo apt install -y git curl` |
| Ubuntu Wks | Ubuntu | apt | `sudo apt install -y git curl docker.io` |
| Splunk | Oracle Linux | dnf | `sudo dnf install -y git curl` |
| Windows boxes | Windows | N/A | Download ZIP or copy from USB |
| VyOS | VyOS | N/A | Read-only - use commands directly |

### Ansible Controller Setup (pick ONE Linux box)

Recommended: **Ubuntu Workstation** (has DHCP, good for central management)

```bash
# Full Ansible controller setup
sudo apt update && sudo apt install -y git curl python3-pip
pip3 install ansible pywinrm requests

# Verify
ansible --version
python3 -c "import winrm; print('pywinrm OK')"

# Clone toolkit
git clone https://github.com/YOUR_REPO/ccdc26.git /opt/ccdc26
cd /opt/ccdc26

# Update inventory with correct IPs/passwords
nano ansible/inventory.ini

# Test connectivity
ansible all -i ansible/inventory.ini -m ping
```

---

## FIRST 15 MINUTES CHECKLIST

### Immediately After Drop Flag (9:00 AM)

```bash
# 1. Access competition stadium
#    URL: https://ccdc.cit.morainevalley.edu
#    Login: v#u1 through v#u8 (# = team number)

# 2. Change ALL passwords immediately!
#    Use a consistent password across the team
#    Example: Cc@c2026!Secure

# 3. On Ubuntu Ecom (first Linux box):
ssh sysadmin@172.20.242.30
# Change password
passwd
# Deploy toolkit
git clone YOUR_REPO /opt/ccdc26  # or copy from USB
cd /opt/ccdc26
chmod +x deploy.sh linux-scripts/**/*.sh
sudo ./linux-scripts/hardening/full-harden.sh
```

### Password Change Commands

**Linux:**
```bash
# Change current user password
passwd

# Change root password
sudo passwd root

# Change all user passwords (careful!)
echo "username:newpassword" | sudo chpasswd
```

**Windows (PowerShell as Admin):**
```powershell
# Change local admin password
net user administrator "NewP@ssw0rd123!"

# Change domain admin (on AD/DNS)
Set-ADAccountPassword -Identity administrator -NewPassword (ConvertTo-SecureString "NewP@ssw0rd123!" -AsPlainText -Force)
```

**Firewalls:**
```
# Palo Alto (via GUI at 172.20.242.150)
Device > Administrators > admin > Change Password

# Cisco FTD (via GUI at 172.20.240.200)
System > Users > Edit admin
```

---

## SPLUNK FORWARDING (Backup SIEM)

The competition has an existing Splunk server at **172.20.242.20**. Set up log forwarding as a backup to Wazuh.

```bash
# Deploy Splunk forwarders to all hosts via Ansible
ansible-playbook -i ansible/inventory.ini ansible/deploy_splunk_forwarders.yml

# Or manually on each Linux host:
sudo ./linux-scripts/tools/splunk-forwarder.sh
# Select option 1 for quick setup

# Or manually on each Windows host (as Admin):
.\windows-scripts\Install-SplunkForwarder.ps1
# Select option 1 for quick setup

# Access Splunk web interface:
# URL: https://172.20.242.20:8000
# Credentials: admin:changeme (check/change!)
```

**Splunk Server Credentials:**
- root: changemenow
- sysadmin: changemenow  
- admin: changeme (Splunk Web)

---

## WAZUH DEPLOYMENT (On Ubuntu Workstation - Primary SIEM)

```bash
# FIRST: Get Ubuntu Workstation's DHCP IP from competition console
# Click on Ubuntu Wks VM, then run: ip addr | grep "inet "
# Note the 172.20.242.X address

# SSH to Ubuntu Workstation (replace X.X.X.X with actual IP)
ssh sysadmin@X.X.X.X

# Quick Wazuh server via Docker
cd /opt/ccdc26/wazuh-content/docker/
docker compose -f generate-certs.yml run --rm generator
docker compose up -d

# Wait 3 minutes, then access (replace X.X.X.X with Ubuntu Wks IP):
# https://X.X.X.X:443
# admin / SecretPassword

# Update inventory.ini with Ubuntu Wks IP, then deploy agents:
cd /opt/ccdc26
# Edit ansible/inventory.ini: change ubuntu-wks ansible_host=X.X.X.X
ansible-playbook -i ansible/inventory.ini ansible/deploy_wazuh.yml \
  -e "wazuh_manager=X.X.X.X"
```

---

## QUICK HARDENING COMMANDS

### Linux (run on each server)
```bash
cd /opt/ccdc26
sudo ./linux-scripts/hardening/full-harden.sh
sudo ./linux-scripts/tools/fail2ban-setup.sh
sudo ./linux-scripts/persistence-hunting/full-hunt.sh
```

### Windows (run on each server)
```powershell
cd C:\ccdc26
.\windows-scripts\hardening\Full-Harden.ps1 -q

# On Domain Controller only:
.\windows-scripts\hardening\AD-Harden.ps1 -q
```

---

## FIREWALL QUICK REFERENCE

### Palo Alto (172.20.242.150)
```
# Access via browser from Ubuntu Wks
# Policies > Security > Add rule

# Quick CLI via SSH:
ssh admin@172.20.242.150
configure
set rulebase security rules BLOCK-BAD from any to any application any action deny
commit
```

### Cisco FTD (172.20.240.200)
```
# Access via browser from Win11 Wks
# https://172.20.102.254/#/login
# Policies > Access Control > Add Rule
```

### Linux iptables/ufw
```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Block specific IP
sudo ufw deny from 10.0.0.100
```

### Windows Firewall
```powershell
# Block IP
New-NetFirewallRule -DisplayName "Block Attacker" -Direction Inbound -RemoteAddress 10.0.0.100 -Action Block

# Allow service
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
```

---

## INCIDENT RESPONSE

### Detect Active Attacks
```bash
# Linux - who's connected
w
netstat -tulpn
ss -tulpn
last -20

# Find suspicious processes
ps auxf | grep -E "(nc|ncat|netcat|/bin/sh|/bin/bash)"
```

```powershell
# Windows - who's connected
query user
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
Get-Process | Where-Object {$_.CPU -gt 50}
```

### Kill Attacker Session
```bash
# Linux
pkill -u suspicioususer
skill -KILL -u suspicioususer

# Find and kill reverse shells
lsof -i -P | grep ESTABLISHED
kill -9 <PID>
```

```powershell
# Windows
logoff <session_id>
Stop-Process -Id <PID> -Force
```

### Incident Report Template
```
INCIDENT REPORT
===============
Time Detected: 
Source IP: 
Destination IP: 
Affected System: 
Description: 

Timeline:
- 

Affected Services/Data:
- 

Remediation Steps Taken:
1. 
2. 
3. 

Preventive Measures:
- 
```

---

## IMPORTANT RULES REMINDERS

1. **DO NOT** change IP addresses or VLANs
2. **DO NOT** scan other team networks (instant DQ)
3. **DO NOT** move services between IPs
4. **MUST** maintain ICMP on all devices (except PA Core)
5. **MUST** report password changes (except root/admin)
6. **MAX** 3 VM scrubs allowed (with penalty)
7. Submit inject responses as **PDF files**

---

## EMERGENCY CONTACTS

| Role | How to Contact |
|------|---------------|
| Tech Support | Submit via NISE inject |
| White Team | NISE notifications |
| VM Scrub Request | Tech Support inject (penalty applies) |

---

## QUICK REFERENCE CARD

```
┌─────────────────────────────────────────────────────────────────────┐
│              RMCCDC 2026 - TEAM 2 (BYU) QUICK REFERENCE             │
├─────────────────────────────────────────────────────────────────────┤
│ NISE Portal:     https://ccdcadmin1.morainevalley.edu               │
│ NISE Accounts:   team02a - team02i                                  │
│ Competition:     https://ccdc.cit.morainevalley.edu                 │
│ Comp Accounts:   v2u1 - v2u8                                        │
│ Public IP Range: 172.25.22.0/24                                     │
├─────────────────────────────────────────────────────────────────────┤
│ LINUX ZONE (behind Palo Alto - 172.20.242.0/24):                    │
│   Ubuntu Ecom:   172.20.242.30  (sysadmin:changeme)    → .22.11     │
│   Fedora Mail:   172.20.242.40  (sysadmin:changeme)    → .22.39     │
│   Splunk:        172.20.242.20  (root:changemenow)     → .22.9      │
│   Ubuntu Wks:    DHCP!          (sysadmin:changeme)  [Wazuh Server] │
│   Palo Alto:     172.20.242.150 (admin:Changeme123)                 │
├─────────────────────────────────────────────────────────────────────┤
│ WINDOWS ZONE (behind Cisco FTD - 172.20.240.0/24):                  │
│   AD/DNS:        172.20.240.102 (administrator:!Password123) → .22.155 │
│   Web 2019:      172.20.240.101 (administrator:!Password123) → .22.140 │
│   FTP 2022:      172.20.240.104 (administrator:!Password123) → .22.162 │
│   Win11 Wks:     172.20.240.100 (administrator:!Password123) → .22.144 │
│   Cisco FTD:     172.20.240.200 (admin:!Changeme123)                │
├─────────────────────────────────────────────────────────────────────┤
│ ROUTER:                                                             │
│   VyOS:          172.16.101.1   (vyos:changeme)                     │
│   External:      172.31.22.2/29  Core: 172.31.22.1                  │
├─────────────────────────────────────────────────────────────────────┤
│ SCORED SERVICES: HTTP, HTTPS, SMTP, POP3, DNS                       │
│ DO NOT CHANGE IPs! DO NOT SCAN OTHER TEAMS!                         │
└─────────────────────────────────────────────────────────────────────┘
```
