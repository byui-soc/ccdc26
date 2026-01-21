# CCDC26 Ansible Automation

Ansible playbooks for rapid deployment of the CCDC26 toolkit across multiple hosts.

## Quick Start (Competition Day)

```bash
# 1. Set your team number in inventory.ini (line: team_number=X)

# 2. Test connectivity to all hosts
ansible all -i inventory.ini -m ping

# 3. IMMEDIATELY: Change all passwords
ansible-playbook -i inventory.ini change_all_passwords.yml -e "new_password=YourSecureP@ss123!"

# 4. Deploy Wazuh agents (after setting up Wazuh server)
ansible-playbook -i inventory.ini deploy_wazuh.yml -e "wazuh_manager=172.20.242.50"

# 5. Deploy hardening to all hosts
ansible-playbook -i inventory.ini deploy_hardening.yml
```

## Directory Structure

```
ansible/
├── setup/
│   └── csv2inv.py              # CSV to inventory converter
├── roles/
│   └── gather/                 # Host fact gathering role
├── templates/
│   └── ossec-linux.conf.j2     # Wazuh agent config template
├── inventory.ini               # Competition hosts (PRE-CONFIGURED!)
├── vars.yml                    # Competition variables
├── change_all_passwords.yml    # Mass password reset (RUN FIRST!)
├── changepw_kick.yml           # Password reset + user creation
├── deploy_hardening.yml        # Deploy linux-scripts
├── deploy_wazuh.yml            # Deploy Wazuh agents
└── gather_facts.yml            # Collect host information
```

## Inventory Setup

### Pre-Configured for RMCCDC 2026

The `inventory.ini` file is **pre-configured** with all competition systems:

**Linux Zone (172.20.242.0/24):**
- `ecom` - Ubuntu E-commerce (HTTP/HTTPS)
- `webmail` - Fedora Webmail (SMTP/POP3)
- `splunk` - Splunk Server (Oracle Linux)
- `ubuntu-wks` - Ubuntu Workstation

**Windows Zone (172.20.240.0/24):**
- `ad-dns` - AD/DNS Server 2019 (DNS)
- `web` - Web Server 2019 (HTTP/HTTPS)
- `ftp` - FTP Server 2022
- `win11-wks` - Windows 11 Workstation

**Network Devices:**
- `paloalto` - Palo Alto Firewall
- `cisco-ftd` - Cisco FTD Firewall
- `vyos` - VyOS Router

### Set Your Team Number

Edit `inventory.ini` and change the team number:

```ini
[all:vars]
team_number=1  # Change to your assigned team number (1-20)
```

## Playbooks

### change_all_passwords.yml (RUN FIRST!)

**Purpose**: Change ALL default passwords across the competition environment

```bash
# Change all passwords to a single secure password
ansible-playbook -i inventory.ini change_all_passwords.yml -e "new_password=YourSecureP@ss123!"
```

This playbook:
- Changes sysadmin/root passwords on all Linux hosts
- Changes administrator password on all Windows hosts
- Changes VyOS router password
- Locks unnecessary Linux accounts
- Reminds you to manually change Palo Alto, Cisco FTD, and Splunk passwords

### changepw_kick.yml

**Purpose**: First-15-minutes critical actions

- Creates competition admin users (ccdcuser1, ccdcuser2)
- Resets ALL user passwords to a prompted value
- Kills all active user sessions

```bash
ansible-playbook -i inventory.ini changepw_kick.yml
# You will be prompted for the new password
```

### deploy_hardening.yml

**Purpose**: Deploy and run hardening scripts

```bash
# Deploy to all Linux hosts
ansible-playbook -i inventory.ini deploy_hardening.yml

# Deploy with specific options
ansible-playbook -i inventory.ini deploy_hardening.yml -e "run_full=true"

# Dry run (check mode)
ansible-playbook -i inventory.ini deploy_hardening.yml --check
```

### deploy_wazuh.yml

**Purpose**: Deploy Wazuh agents to all hosts

```bash
# Deploy agents (Linux and Windows)
ansible-playbook -i inventory.ini deploy_wazuh.yml -e "wazuh_manager=10.0.0.100"

# With registration password
ansible-playbook -i inventory.ini deploy_wazuh.yml \
  -e "wazuh_manager=10.0.0.100" \
  -e "wazuh_registration_password=MySecretPassword"
```

### gather_facts.yml

**Purpose**: Collect reconnaissance data from all hosts

```bash
ansible-playbook -i inventory.ini gather_facts.yml
# Creates JSON files in ./collected_facts/
```

## Variables

Edit `vars.yml` or pass via command line:

```bash
# Override variables
ansible-playbook playbook.yml -e "wazuh_manager=10.0.0.100" -e "temp_password=NewPass123"
```

Key variables:
- `wazuh_manager`: IP of Wazuh manager
- `toolkit_dest`: Where to deploy scripts (default: /opt/ccdc26)
- `competition_users`: List of users to create

## Requirements

### Ansible Controller

```bash
# Install Ansible
pip3 install ansible

# For Windows hosts
pip3 install pywinrm
```

### Target Hosts

**Linux**: SSH access with sudo
**Windows**: WinRM enabled (port 5985)

Enable WinRM on Windows:
```powershell
winrm quickconfig
Enable-PSRemoting -Force
```

## Tips for Competition

1. **Pre-create inventory template** with expected host ranges
2. **Test locally first** with a VM
3. **Run changepw_kick.yml immediately** on competition start
4. **Use --limit** to target specific hosts: `--limit web1,db1`
5. **Use -v** for verbose output to debug issues
