# CCDC26 Defense Toolkit

Hardening, monitoring, and incident response scripts for CCDC 2026. Supports Linux and Windows systems with centralized management via Ansible.

**Competition Day?** See [QUICKREF.md](QUICKREF.md) for credentials, commands, and what each option does.

---

## Prerequisites

Install on ONE machine (your Ansible controller):

```bash
# Fedora/RHEL
sudo dnf install -y git python3-pip && pip3 install ansible pywinrm

# Ubuntu/Debian
sudo apt install -y git python3-pip && pip3 install ansible pywinrm
```

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_REPO/ccdc26.git /opt/ccdc26
cd /opt/ccdc26

# 2. Run the toolkit
sudo ./deploy.sh

# 3. Select an option:
#    1) Quick Harden  - Hardens THIS machine (no passwords changed)
#    2) Ansible       - Manage ALL machines remotely
#    3) Advanced      - Individual tools and scripts
```

---

## What Each Option Does

### Main Menu

| Option | Runs On | What It Does |
|--------|---------|--------------|
| **1) Quick Harden** | This machine | Hardens SSH, firewall, services, permissions, kernel. Does NOT change passwords. |
| **2) Ansible Control Panel** | Other machines via SSH/WinRM | Manage multiple machines at once (passwords, hardening, agents) |
| **3) Advanced Options** | This machine | Individual scripts, SIEM agents, persistence hunting, IR tools |

### Ansible Menu (Option 2)

| Option | What It Does |
|--------|--------------|
| **1) Generate inventory** | Convert CSV to inventory.ini |
| **2) Test connectivity** | Ping all machines to verify Ansible can reach them |
| **3) Password Reset** | Change ALL passwords on ALL machines + kick active sessions |
| **4) Deploy Hardening** | Copy scripts to all machines (optionally run them) |
| **5) Deploy Wazuh Agents** | Install Wazuh agent on all machines |
| **6) Deploy Splunk Forwarders** | Install Splunk forwarder on all machines |
| **7) Gather Facts** | Collect system info from all machines |

---

## How Ansible Works

```
Your Machine (Controller)          Other Machines (Targets)
┌─────────────────────┐            ┌─────────────────┐
│  ./deploy.sh        │    SSH     │  Ubuntu Ecom    │
│  Option 2: Ansible  │───────────>│  172.20.242.30  │
│                     │            └─────────────────┘
│  Reads inventory.ini│    SSH     ┌─────────────────┐
│  Runs playbooks     │───────────>│  Fedora Webmail │
│                     │            │  172.20.242.40  │
└─────────────────────┘            └─────────────────┘
                           WinRM   ┌─────────────────┐
                       ───────────>│  Windows AD/DNS │
                                   │  172.20.240.102 │
                                   └─────────────────┘
```

- **Controller**: The machine where you run `./deploy.sh` and select Ansible options
- **Targets**: All other machines listed in `ansible/inventory.ini`
- Ansible connects via SSH (Linux) or WinRM (Windows) on the internal network

---

## Windows Scripts

Windows machines don't use `deploy.sh`. Copy the toolkit to `C:\ccdc26` and run PowerShell scripts directly.

### Quick Start (Windows)

```powershell
# Copy toolkit to C:\ccdc26 (via download)

# Run as Administrator:
cd C:\ccdc26\windows-scripts

# Harden any Windows machine
.\hardening\Full-Harden.ps1 -q

# Harden Domain Controller (AD-specific)
.\hardening\AD-Harden.ps1 -q

# Install Wazuh agent
.\Install-WazuhAgent.ps1

# Install Splunk forwarder
.\Install-SplunkForwarder.ps1
```

### Windows Scripts Reference

| Script | What It Does |
|--------|--------------|
| `Full-Harden.ps1` | Patches CVEs (EternalBlue, PrintNightmare, Mimikatz), enables Defender ASR rules, disables dangerous services, removes backdoors |
| `AD-Harden.ps1` | Domain Controller only: Zerologon/noPac patches, Kerberos hardening, privileged group cleanup, LDAP signing |
| `Install-WazuhAgent.ps1` | Installs Wazuh agent for security monitoring |
| `Install-SplunkForwarder.ps1` | Installs Splunk forwarder (backup SIEM) |
| `lib/passwords.ps1` | Generates deterministic passwords from username+salt |

See [windows-scripts/README.md](windows-scripts/README.md) for full details.

---

## Repository Structure

```
ccdc26/
├── deploy.sh              # Main entry point (Linux)
├── QUICKREF.md            # Competition quick reference
├── ansible/               # Playbooks for remote management
│   ├── inventory.ini      # Machine IPs and credentials
│   └── changepw_kick.yml  # Password reset playbook
├── linux-scripts/
│   ├── hardening/         # System hardening scripts
│   ├── monitoring/        # Real-time monitoring
│   ├── persistence-hunting/  # Find attacker backdoors
│   └── incident-response/ # IR tools
└── windows-scripts/
    ├── hardening/
    │   ├── Full-Harden.ps1   # Main Windows hardening
    │   ├── AD-Harden.ps1     # Domain Controller hardening
    │   └── lib/              # Shared functions
    ├── Install-WazuhAgent.ps1
    └── Install-SplunkForwarder.ps1
```

---

## Key Commands

```bash
# Harden this machine
sudo ./deploy.sh            # Then select 1

# Change all passwords (from Ansible controller)
sudo ./deploy.sh            # Then select 2 -> 3

# Run hardening on all machines
sudo ./deploy.sh            # Then select 2 -> 4 -> 2

# Command line shortcuts
sudo ./deploy.sh --quick    # Quick harden (no menu)
sudo ./deploy.sh --help     # Show help
```
