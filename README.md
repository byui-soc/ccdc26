# CCDC26 Defense Toolkit

Comprehensive toolkit for 2026 CCDC season. Includes Linux and Windows system hardening, monitoring, incident response, and centralized security monitoring with **Wazuh** (free, open-source SIEM/XDR).

> **Competition Day?** See [COMPETITION-CHEATSHEET.md](COMPETITION-CHEATSHEET.md) for quick reference with all IPs, credentials, and commands.

---

## Table of Contents

1. [What is This?](#what-is-this)
2. [Prerequisites](#prerequisites)
3. [Getting Started](#getting-started)
4. [Wazuh Setup (Step-by-Step)](#wazuh-setup-step-by-step)
5. [Competition Workflow](#competition-workflow)
6. [Repository Structure](#repository-structure)
7. [Hardening Scripts](#hardening-scripts)
8. [Monitoring](#monitoring)
9. [Verification & Testing](#verification--testing)
10. [Troubleshooting](#troubleshooting)
11. [Network & Firewall Configuration](#network--firewall-configuration)
12. [Ports Reference](#ports-reference)

---

## What is This?

This toolkit helps you **defend systems during CCDC competitions**. It includes:

- **Hardening scripts** - Lock down Linux and Windows systems against attacks
- **Wazuh SIEM** - Centralized dashboard to see security alerts from ALL your systems in one place
- **Monitoring tools** - Detect suspicious activity in real-time
- **Incident response** - Tools to investigate and respond to attacks

### What is Wazuh?

**Wazuh** is a free, open-source security platform. It:
- Collects logs from all your systems (Linux, Windows)
- Alerts you when something suspicious happens (failed logins, new users, file changes)
- Shows everything in a web dashboard so you can monitor all systems at once
- Can automatically block attackers (e.g., after 5 failed SSH logins)

**Why do we need it?** During CCDC, you'll have 10+ systems to defend. You can't watch terminal windows on all of them. Wazuh collects everything centrally so you see attacks as they happen.

### Backup SIEM: Splunk

The competition environment includes a **Splunk server at 172.20.242.20**. We also forward logs there as a backup:
- Primary SIEM: **Wazuh** (deployed on Ubuntu Workstation)
- Backup SIEM: **Splunk** (competition server at 172.20.242.20)

This gives you redundancy - if one SIEM has issues, you still have visibility through the other.

---

## Prerequisites

### On Your Workstation (where you run Ansible)

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y git ansible python3 python3-pip sshpass
pip3 install pywinrm

# Arch Linux
sudo pacman -S git ansible python python-pip sshpass
pip install pywinrm

# Fedora/RHEL
sudo dnf install -y git ansible python3 python3-pip sshpass
pip3 install pywinrm
```

### On the Wazuh Server (dedicated system recommended)

**Minimum Requirements:**
| Resource | Docker Install | Full Install |
|----------|----------------|--------------|
| RAM | 4GB minimum, 8GB recommended | 8GB minimum |
| CPU | 2 cores minimum, 4 recommended | 4 cores |
| Disk | 50GB minimum | 50GB minimum |
| OS | Any Linux with Docker | Ubuntu 20.04+, RHEL 8+, Debian 10+ |

```bash
# Install Docker (if using Docker method)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# LOG OUT AND BACK IN after this command

# Verify Docker works
docker run hello-world
```

### On Target Hosts

**Linux:** SSH access with a user that has sudo privileges
**Windows:** WinRM enabled (run these commands as Administrator):

```powershell
# Enable WinRM on Windows hosts
winrm quickconfig -force
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

---

## Getting Started

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_ORG/ccdc26.git
cd ccdc26
chmod +x deploy.sh linux-scripts/**/*.sh
```

### Step 2: Choose Your Path

| Scenario | What to Do |
|----------|------------|
| **Single Linux system** | Run `sudo ./deploy.sh` and follow the menu |
| **Single Windows system** | Run `.\deploy.ps1` as Administrator |
| **Multiple systems (competition)** | Set up Wazuh server first, then use Ansible |

### Step 3: Quick Single-System Hardening

```bash
# Linux - Interactive menu
sudo ./deploy.sh

# Linux - Quick mode (runs everything with defaults)
sudo ./linux-scripts/hardening/full-harden.sh
```

```powershell
# Windows - Interactive menu
.\deploy.ps1

# Windows - Quick mode
.\windows-scripts\hardening\Full-Harden.ps1 -q
```

---

## Wazuh Setup (Step-by-Step)

### Overview

You need ONE Wazuh server that collects logs from ALL other systems. The other systems run Wazuh "agents" that send logs to the server.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Linux Host 1   │     │  Linux Host 2   │     │  Windows Host   │
│  (Wazuh Agent)  │     │  (Wazuh Agent)  │     │  (Wazuh Agent)  │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │ Port 1514/1515
                                 ▼
                    ┌────────────────────────┐
                    │    WAZUH SERVER        │
                    │  ┌─────────────────┐   │
                    │  │ Manager         │   │  ← Receives agent data
                    │  │ Indexer         │   │  ← Stores/indexes logs
                    │  │ Dashboard       │   │  ← Web UI (port 443)
                    │  └─────────────────┘   │
                    └────────────────────────┘
```

### Step 1: Deploy Wazuh Server

Pick ONE system to be your Wazuh server. This should be a system with good resources (8GB RAM ideally).

#### Option A: Docker (Fastest - Good for Practice/Competition)

```bash
# 1. Navigate to docker directory
cd wazuh-content/docker/

# 2. Generate SSL certificates (required, only do once)
docker compose -f generate-certs.yml run --rm generator

# 3. Start all Wazuh services
docker compose up -d

# 4. Wait 2-3 minutes for services to start, then check status
docker compose ps

# 5. Access the dashboard
# Open browser: https://YOUR_SERVER_IP:443
# Username: admin
# Password: SecretPassword
```

**Expected output from `docker compose ps`:**
```
NAME                    STATUS
wazuh-manager           Up (healthy)
wazuh-indexer           Up (healthy)  
wazuh-dashboard         Up (healthy)
```

#### Option B: Package Installation (Production/Persistent)

```bash
# 1. Run the server setup script
sudo ./linux-scripts/tools/wazuh-server.sh

# 2. Select option 2 for full installation
# 3. Follow the prompts - it will:
#    - Install Wazuh Manager
#    - Install Wazuh Indexer (OpenSearch)
#    - Install Wazuh Dashboard
#    - Configure everything automatically

# 4. Note the passwords shown at the end!
```

### Step 2: Get Your Wazuh Server IP

You'll need this IP for all agent installations.

```bash
# On the Wazuh server, find its IP
ip addr show | grep "inet " | grep -v 127.0.0.1
# Look for something like: inet 192.168.1.100/24
# Your Wazuh manager IP is: 192.168.1.100
```

### Step 3: Deploy Agents to Linux Hosts

**Method A: One at a time (manual)**

```bash
# 1. SSH to the Linux host
ssh admin@192.168.1.50

# 2. Copy the toolkit or just the agent script
# 3. Edit the script to set your manager IP
nano linux-scripts/tools/wazuh-agent.sh
# Change: WAZUH_MANAGER="CHANGE_ME"
# To:     WAZUH_MANAGER="192.168.1.100"  (your actual server IP)

# 4. Run the agent setup
sudo ./linux-scripts/tools/wazuh-agent.sh
# Select option 1 for quick setup
```

**Method B: Using Ansible (all hosts at once)**

```bash
# 1. Edit the inventory file with your hosts
nano ansible/inventory.ini

# Add your hosts like this:
# [linux]
# web1 ansible_host=192.168.1.50 ansible_user=admin ansible_password=changeme
# db1 ansible_host=192.168.1.51 ansible_user=admin ansible_password=changeme

# 2. Test connectivity
ansible linux -i ansible/inventory.ini -m ping

# 3. Deploy agents to all Linux hosts
ansible-playbook -i ansible/inventory.ini ansible/deploy_wazuh.yml \
  -e "wazuh_manager=192.168.1.100"
```

### Step 4: Deploy Agents to Windows Hosts

**Method A: One at a time (manual)**

```powershell
# 1. Open PowerShell as Administrator
# 2. Navigate to the toolkit
cd C:\path\to\ccdc26\windows-scripts

# 3. Edit the script to set your manager IP
notepad Install-WazuhAgent.ps1
# Change: $WAZUH_MANAGER = "CHANGE_ME"
# To:     $WAZUH_MANAGER = "192.168.1.100"

# 4. Run the setup
.\Install-WazuhAgent.ps1
# Select option 1 for quick setup
```

**Method B: Using Ansible**

```bash
# 1. Add Windows hosts to inventory
# [windows]
# dc1 ansible_host=192.168.1.60 ansible_user=administrator ansible_password=Password123

# 2. Deploy to all Windows hosts
ansible-playbook -i ansible/inventory.ini ansible/deploy_wazuh.yml \
  -e "wazuh_manager=192.168.1.100"
```

### Step 5: Verify Agents are Connected

1. Open the Wazuh Dashboard: `https://YOUR_SERVER_IP:443`
2. Login with `admin` / `SecretPassword` (or your custom password)
3. Click **Agents** in the left menu
4. You should see all your agents listed with status **Active**

```bash
# Or check from command line on the Wazuh server
sudo /var/ossec/bin/agent_control -l

# Expected output:
# Available agents:
#    ID: 001, Name: web1, IP: 192.168.1.50, Active
#    ID: 002, Name: db1, IP: 192.168.1.51, Active
```

---

## Competition Workflow (RMCCDC 2026)

### Before Drop Flag (8:00 AM MST)

```bash
# 1. Login to NISE Portal
#    URL: https://ccdcadmin1.morainevalley.edu
#    Accounts: team02a - team02i (Team 2)
#    Respond to "Welcome" inject and complete survey

# 2. Wait for Drop Flag at 9:00 AM MST
```

### First 15 Minutes After Drop Flag (CRITICAL)

```bash
# 1. Access competition: https://ccdc.cit.morainevalley.edu
#    Login: v2u1 - v2u8 (Team 2)

# 2. IMMEDIATELY change all passwords
cd ansible/
ansible-playbook -i inventory.ini change_all_passwords.yml -e "new_password=YourSecureP@ss123!"

# 3. Start Wazuh on Ubuntu Workstation (DHCP - check actual IP first!)
#    From competition console, check Ubuntu Wks IP with: ip addr
ssh sysadmin@<UBUNTU_WKS_IP>
cd /opt/ccdc26/wazuh-content/docker/
docker compose -f generate-certs.yml run --rm generator
docker compose up -d

# 4. Deploy Wazuh agents (update wazuh_manager with actual Ubuntu Wks IP)
ansible-playbook -i inventory.ini deploy_wazuh.yml -e "wazuh_manager=<UBUNTU_WKS_IP>"

# 5. Quick harden all Linux hosts
ansible linux -i inventory.ini -m shell -a "cd /opt/ccdc26 && ./hardening/full-harden.sh" --become
```

### Next 30 Minutes (Important)

```powershell
# 6. Windows hardening (run on each Windows server)
.\windows-scripts\hardening\Full-Harden.ps1 -q

# 7. AD hardening (on AD/DNS server only)
.\windows-scripts\hardening\AD-Harden.ps1 -q
```

```bash
# 8. Hunt for persistence on all Linux hosts
sudo ./linux-scripts/persistence-hunting/full-hunt.sh

# 9. Set up fail2ban
sudo ./linux-scripts/tools/fail2ban-setup.sh
```

### Ongoing

- **Monitor Wazuh dashboard constantly** (https://UBUNTU_WKS_IP:443)
- Check NISE portal for new injects
- Submit incident reports for any Red Team activity detected
- Re-run persistence hunting every 30 minutes
- Document everything for scoring

---

## Repository Structure

```
ccdc26/
├── deploy.sh                   # Master entry point (Linux)
├── deploy.ps1                  # Master entry point (Windows)
├── ansible/                    # Ansible automation
│   ├── inventory.ini           # Host inventory (EDIT THIS!)
│   ├── vars.yml                # Configuration variables
│   ├── deploy_wazuh.yml        # Deploy Wazuh agents
│   ├── deploy_hardening.yml    # Deploy hardening scripts
│   └── changepw_kick.yml       # Mass password reset
├── linux-scripts/              # Linux defense toolkit
│   ├── hardening/              # System hardening
│   │   ├── full-harden.sh      # Run ALL hardening
│   │   ├── users.sh            # User lockdown
│   │   ├── ssh.sh              # SSH hardening
│   │   ├── firewall.sh         # Firewall setup
│   │   ├── services.sh         # Disable bad services
│   │   ├── permissions.sh      # File permissions
│   │   └── kernel.sh           # Kernel hardening
│   ├── services/               # Service-specific hardening
│   │   ├── harden-webserver.sh # Apache/Nginx
│   │   ├── harden-database.sh  # MySQL/PostgreSQL
│   │   ├── harden-mail.sh      # Postfix/Dovecot
│   │   ├── harden-ftp.sh       # vsftpd/ProFTPD
│   │   └── harden-dns.sh       # BIND
│   ├── tools/                  # Security tools
│   │   ├── wazuh-agent.sh      # Wazuh agent setup
│   │   ├── wazuh-server.sh     # Wazuh server setup
│   │   ├── fail2ban-setup.sh   # Fail2ban
│   │   └── security-tools.sh   # auditd, rkhunter, etc.
│   ├── persistence-hunting/    # Find backdoors
│   │   ├── full-hunt.sh        # Run all checks
│   │   ├── cron-audit.sh       # Cron jobs
│   │   ├── service-audit.sh    # Services
│   │   └── user-audit.sh       # Users
│   ├── monitoring/             # Local monitoring
│   └── incident-response/      # IR tools
├── windows-scripts/            # Windows defense toolkit
│   ├── hardening/
│   │   ├── Full-Harden.ps1     # Complete hardening
│   │   ├── AD-Harden.ps1       # Domain Controller
│   │   └── lib/                # Utility functions
│   └── Install-WazuhAgent.ps1  # Wazuh agent setup
└── wazuh-content/              # Wazuh SIEM content
    ├── rules/                  # Custom detection rules
    │   └── ccdc-custom-rules.xml
    ├── docker/                 # Quick server deployment
    │   ├── docker-compose.yml
    │   └── generate-certs.yml
    └── README.md               # Detailed Wazuh docs
```

---

## Hardening Scripts

### Linux (`./linux-scripts/hardening/`)

| Script | What It Does |
|--------|--------------|
| `full-harden.sh` | **Runs everything below** - use this first |
| `users.sh` | Disables unused accounts, sets strong passwords, removes unauthorized sudo |
| `ssh.sh` | Disables root login, changes port, requires key auth |
| `firewall.sh` | Enables firewall, blocks all except needed ports |
| `services.sh` | Disables telnet, rsh, rlogin, and other dangerous services |
| `permissions.sh` | Fixes SUID/SGID bits, secures /etc files |
| `kernel.sh` | Enables ASLR, disables IP forwarding, hardens network stack |

### Windows (`.\windows-scripts\hardening\`)

| Script | What It Does |
|--------|--------------|
| `Full-Harden.ps1` | **Complete hardening** - patches CVEs, enables Defender, removes backdoors |
| `AD-Harden.ps1` | Domain Controller specific - Kerberos, LDAP signing, privileged groups |
| `lib\auditing.ps1` | Enables all Windows audit policies, PowerShell logging |
| `lib\passwords.ps1` | Generates deterministic passwords from a salt |

### CVEs Patched by Windows Scripts

| CVE | Name | Risk |
|-----|------|------|
| MS17-010 | EternalBlue | Remote code execution via SMB |
| CVE-2021-34527 | PrintNightmare | Remote code execution via Print Spooler |
| CVE-2020-1472 | Zerologon | Domain takeover |
| CVE-2021-42278/42287 | noPac | Domain privilege escalation |

---

## Monitoring

### Wazuh Dashboard Views

Once logged into Wazuh (`https://YOUR_SERVER:443`), check these sections:

| Section | What to Look For |
|---------|------------------|
| **Security Events** | Real-time alerts - brute force, new users, privilege escalation |
| **File Integrity** | Changes to /etc/passwd, /etc/shadow, cron files |
| **Vulnerabilities** | Unpatched CVEs on your systems |
| **MITRE ATT&CK** | Attacks mapped to techniques |
| **Agents** | Make sure all agents show "Active" |

### Custom CCDC Rules

We include 40+ custom detection rules for CCDC-specific attacks:

- Brute force detection (5+ failed logins in 5 minutes)
- After-hours login attempts
- New user creation
- Sudoers file changes
- Cron job modifications
- Web shell detection
- Reverse shell detection
- Encoded PowerShell commands

---

## Verification & Testing

### Check Wazuh Server is Running

```bash
# Docker method
docker compose ps
# All services should show "Up (healthy)"

# Package method
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

### Check Agent is Connected

```bash
# On the agent (Linux)
sudo systemctl status wazuh-agent
sudo cat /var/ossec/logs/ossec.log | tail -20
# Look for: "Connected to the server"

# On the server
sudo /var/ossec/bin/agent_control -l
```

```powershell
# On the agent (Windows)
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

### Generate a Test Alert

```bash
# On any Linux agent - trigger a failed SSH login alert
ssh fakeuser@localhost
# Enter wrong password 5 times

# Check Wazuh dashboard - you should see a brute force alert within 1 minute
```

### Test Hardening Worked

```bash
# Check SSH doesn't allow root
ssh root@localhost  # Should be denied

# Check firewall is active
sudo ufw status  # or: sudo firewall-cmd --state

# Check dangerous services are disabled
systemctl is-enabled telnet  # Should show "disabled" or "not found"
```

---

## Troubleshooting

### Wazuh Dashboard Won't Load

```bash
# Check if services are running
docker compose ps  # or: systemctl status wazuh-dashboard

# Check logs
docker compose logs wazuh-dashboard | tail -50

# Common fix: Wait longer (can take 3-5 minutes on slow systems)
# Common fix: Check port 443 isn't blocked
curl -k https://localhost:443
```

### Agent Won't Connect to Manager

```bash
# 1. Check agent can reach manager
ping YOUR_MANAGER_IP
nc -zv YOUR_MANAGER_IP 1514  # Should show "succeeded"

# 2. Check manager IP is correct in agent config
cat /var/ossec/etc/ossec.conf | grep -A5 "<server>"

# 3. Check agent service
sudo systemctl restart wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log

# 4. Check firewall on manager allows 1514/1515
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
```

### Ansible Can't Connect to Hosts

```bash
# Test SSH manually first
ssh admin@192.168.1.50

# For Windows, test WinRM
ansible windows -i inventory.ini -m win_ping

# Common Windows fix: Enable WinRM
# On Windows host (as Admin):
winrm quickconfig -force
Enable-PSRemoting -Force
```

### "Permission Denied" Errors

```bash
# Make scripts executable
chmod +x deploy.sh
chmod +x linux-scripts/**/*.sh

# Run as root
sudo ./deploy.sh
```

### Docker Compose Errors

```bash
# "permission denied" - add user to docker group
sudo usermod -aG docker $USER
# LOG OUT AND BACK IN

# "port already in use" - check what's using the port
sudo lsof -i :443
sudo lsof -i :9200

# Reset everything
docker compose down -v
docker compose up -d
```

---

## Network & Firewall Configuration

### Ports to Open on Wazuh Server

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 443/tcp    # Dashboard
sudo ufw allow 1514/tcp   # Agent communication
sudo ufw allow 1515/tcp   # Agent enrollment
sudo ufw allow 55000/tcp  # API (optional)
sudo ufw enable

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo firewall-cmd --permanent --add-port=1515/tcp
sudo firewall-cmd --reload
```

### Ports to Open on Agents

Agents only need **outbound** access to the manager. No inbound ports required.

```bash
# If agents have strict outbound firewalls, allow:
# - TCP 1514 to manager (events)
# - TCP 1515 to manager (enrollment)
```

### Windows Firewall

```powershell
# Usually not needed (outbound is allowed by default)
# But if blocked:
New-NetFirewallRule -DisplayName "Wazuh Agent" -Direction Outbound -RemotePort 1514,1515 -Protocol TCP -Action Allow
```

---

## Ports Reference

| Port | Service | Direction | Purpose |
|------|---------|-----------|---------|
| 22 | SSH | Inbound | Remote administration |
| 443 | Wazuh Dashboard | Inbound | HTTPS web interface |
| 1514 | Wazuh Manager | Inbound (server) | Agent event data |
| 1515 | Wazuh Manager | Inbound (server) | Agent enrollment/registration |
| 5985 | WinRM | Inbound | Ansible to Windows |
| 9200 | Wazuh Indexer | Internal | OpenSearch API (don't expose) |
| 55000 | Wazuh API | Optional | REST API for automation |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│                    CCDC26 QUICK REFERENCE                       │
├─────────────────────────────────────────────────────────────────┤
│ START WAZUH SERVER (Docker):                                    │
│   cd wazuh-content/docker/                                      │
│   docker compose -f generate-certs.yml run --rm generator       │
│   docker compose up -d                                          │
│   Dashboard: https://SERVER_IP:443 (admin/SecretPassword)       │
├─────────────────────────────────────────────────────────────────┤
│ DEPLOY AGENTS:                                                  │
│   ansible-playbook -i ansible/inventory.ini \                   │
│     ansible/deploy_wazuh.yml -e "wazuh_manager=SERVER_IP"       │
├─────────────────────────────────────────────────────────────────┤
│ MASS PASSWORD RESET:                                            │
│   ansible-playbook -i ansible/inventory.ini changepw_kick.yml   │
├─────────────────────────────────────────────────────────────────┤
│ QUICK HARDEN LINUX:                                             │
│   sudo ./linux-scripts/hardening/full-harden.sh                 │
├─────────────────────────────────────────────────────────────────┤
│ QUICK HARDEN WINDOWS:                                           │
│   .\windows-scripts\hardening\Full-Harden.ps1 -q                │
├─────────────────────────────────────────────────────────────────┤
│ HUNT FOR BACKDOORS:                                             │
│   sudo ./linux-scripts/persistence-hunting/full-hunt.sh         │
├─────────────────────────────────────────────────────────────────┤
│ CHECK AGENT STATUS:                                             │
│   sudo /var/ossec/bin/agent_control -l                          │
└─────────────────────────────────────────────────────────────────┘
```
