# CCDC26 Pre-Game Checklist & Findings

**Early Access Session Date:** January 21, 2026  
**Team:** Team 2 (BYU)  
**Competition Date:** January 24, 2026

---

## 🚨 CRITICAL FINDINGS - MALWARE DISCOVERED

### 1. Startup_Check Backdoor/Worm

**PRIORITY: CRITICAL - DISABLE IMMEDIATELY ON GAME START**

A sophisticated persistence mechanism was discovered pre-installed on Linux systems:

**Location:** `/etc/startup_check.py` with systemd service `/etc/systemd/system/startup_check.service`

**Behavior:**
- Runs every 10 minutes (600 seconds)
- Reads configuration from `/etc/config.txt`:
  - First line: local file to rename to `.SAVE` (e.g., `/var/lib/startup.sh`)
  - Subsequent lines: remote machines in format `ip,username,password`
- For each remote machine:
  1. Attempts SSH connection (password or key-based)
  2. Checks if `/usr/share/startup_check-installer.sh` exists on remote
  3. If missing, copies the installer script via SFTP
  4. Executes the installer (which recreates the malware on remote system)
  5. Sets file permissions to make it executable
- Renames local target file (persistence mechanism)
- Logs to `/var/log/startup_check.log` and systemd journal with message "Startup Files Checked - Do Not Restart"

**Affected Machines:**
- Ubuntu Ecom (172.20.242.30) ✓ CONFIRMED
- Ubuntu Workstation (172.20.242.38) ✓ CONFIRMED  
- Fedora Webmail (172.20.242.40) - LIKELY

**Config File Found on Ubuntu Ecom:**
```
/var/lib/startup.sh
172.20.242.254,root,
172.20.242.30,root,
172.20.242.40,root,
```

**Installer Script:** `/usr/share/startup_check-installer.sh`
- Creates the Python backdoor script
- Creates the systemd service
- Enables and starts the service

**Immediate Actions on Game Start:**
```bash
# On EACH Linux machine:

# 1. Stop and disable the service
sudo systemctl stop startup_check.service
sudo systemctl disable startup_check.service

# 2. Remove malware files
sudo rm -f /etc/startup_check.py
sudo rm -f /etc/systemd/system/startup_check.service
sudo rm -f /usr/share/startup_check-installer.sh
sudo rm -f /etc/config.txt
sudo rm -f /var/log/startup_check.log

# 3. Reload systemd
sudo systemctl daemon-reload

# 4. Check for renamed files
ls -la /var/lib/*.SAVE
# If found, investigate before restoring

# 5. Verify removal
systemctl status startup_check.service
```

**Prevention:**
This appears to be a pre-configured vulnerability/backdoor (not red team activity since the game hasn't started). Based on research, CCDC typically includes misconfigurations but deliberate backdoors in startup scripts are concerning. Monitor for re-creation during the competition.

---

## 🔐 SSH SECURITY ISSUES

### 2. Passwordless SSH Keys Found

**Ubuntu Ecom SSH Configuration:**
- File: `/home/sysadmin/.ssh/authorized_keys`
- Contains: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC9PY569t3xZynA5FGL0d1F1xxa8THJ0R47UzMckLU default SSH key for various and other functions as requtred`
- This key allows passwordless SSH access as `sysadmin` from ANY machine with the private key

**Immediate Actions on Game Start:**
```bash
# On EACH Linux machine:

# 1. Remove all authorized_keys
sudo find / -name "authorized_keys" 2>/dev/null -exec echo "=== {} ===" \; -exec cat {} \;
sudo find /home -name "authorized_keys" -delete
sudo find /root -name "authorized_keys" -delete

# 2. Check for suspicious SSH keys
sudo find / -name "id_*" -o -name "*.pem" 2>/dev/null

# 3. Disable SSH key authentication temporarily (if needed)
sudo sed -i 's/^PubkeyAuthentication yes/PubkeyAuthentication no/' /etc/ssh/sshd_config
sudo systemctl reload sshd
```

---

## 👤 USER ENUMERATION FINDINGS

### 3. UID 0 Accounts (Root Equivalents)

**Ubuntu Workstation:**
From the provided screenshot, the following UID 0 accounts were found:
- `root` (normal)
- `nobody` - **SUSPICIOUS** (UID 65534, should NOT be UID 0)
- Potentially others with GID 65534

**Immediate Actions:**
```bash
# Find all UID 0 accounts
awk -F: '$3 == 0 {print}' /etc/passwd

# Only 'root' should have UID 0
# Remove or disable any others:
sudo userdel -r suspicioususer

# Or lock the account:
sudo usermod -L suspicioususer
```

---

## 📡 ANSIBLE CONNECTIVITY ISSUES

### 4. Missing Dependencies

**Problem:** Ansible cannot connect without `sshpass` for password-based authentication.

**Solution:**
```bash
# On Ubuntu (Ansible controller):
sudo apt install -y sshpass

# Verify installation:
which sshpass
```

### 5. SSH Host Key Checking

**Problem:** Ansible fails with "Please add this host's fingerprint to your known_hosts file" error.

**Solutions:**

**Option A: Disable host key checking globally (CCDC acceptable):**
```bash
export ANSIBLE_HOST_KEY_CHECKING=False
```

**Option B: Update ansible.cfg:**
```ini
[defaults]
host_key_checking = False
```

**Option C: Accept keys manually first:**
```bash
# From Ansible controller, SSH to each machine once:
ssh sysadmin@172.20.242.30  # Type 'yes' to accept
ssh sysadmin@172.20.242.40
# etc.
```

### 6. Become (Sudo) Password Issues

**Problem:** Some machines fail with "Missing sudo password" error.

**Current Status:**
- `ubuntu-wks`, `ecom`, `webmail` - Missing sudo password in inventory
- User `sysadmin` has NOPASSWD sudo on most machines (verified on Ubuntu workstation)

**Solution in inventory.ini:**
```ini
# For machines without NOPASSWD sudo:
ubuntu-wks ansible_become_password=changeme

# Or set globally in deploy.sh:
--ask-become-pass
```

---

## 🪟 WINDOWS CONNECTIVITY

### 7. WinRM Not Configured

**Problem:** Windows machines cannot be managed by Ansible because WinRM is not enabled or not accepting remote connections.

**Windows 11 Workstation Status:**
- WinRM service: ✓ NOW ENABLED (was stopped)
- Firewall: ✓ CONFIGURED
- Listener: ✓ HTTP on port 5985

**Immediate Actions on Game Start:**

Run on EACH Windows machine as Administrator:

```powershell
# Quick setup:
cd C:\ccdc26\windows-scripts
.\Setup-WinRM-Ansible.ps1

# Or manual setup:
winrm quickconfig -y

# Enable firewall rule for management subnet:
New-NetFirewallRule -Name "CCDC-WinRM-Ansible" `
    -DisplayName "WinRM (HTTP-In) - CCDC Ansible Management" `
    -Enabled True `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5985 `
    -RemoteAddress 172.20.242.0/24 `
    -Action Allow

# Configure WinRM to accept connections:
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Restart WinRM:
Restart-Service WinRM
```

**Test from Ansible controller:**
```bash
ansible windows -i ansible/inventory.ini -m win_ping
```

---

## 🛒 APPLICATION FINDINGS

### 9. OpenCart E-Commerce Platform

**Location:** Ubuntu Ecom Server (172.20.242.30)

**Discovered:** 
- Running Apache httpd 2.4.58
- OpenCart admin panel at: `http://172.20.242.30/admin`
- Username/password login form visible

**Confirmed from Database Inspection:**
- Database name: `opencart`
- Admin table: `oc_user`
- Admin username: `admin` (confirmed)
- Admin email: `admin@example.com`
- Password hashing: **bcrypt** (`$2y$10$...`) - NOT MD5!
- Account created: 2025-10-17 04:45:46

**Admin Panel Credentials:**
- Username: `admin` (confirmed)
- Password to try: `admin`, `password`, `demo`, `Password123`

**Suspicious Files Found in /home/sysadmin:**

1. **`install-ssh-req.sh`** ⚠️ MALWARE-RELATED
   - Installs `python3-paramiko` and `openssh-server`
   - Paramiko is the SAME library used by startup_check malware
   - Likely used to install malware dependencies
   - **Remove immediately on game start**

2. **`opencart-master/` directory and `master.zip`**
   - OpenCart source code  
   - Exposes version information to red team
   - **Move to /root/backup/ or remove**

**Security Risks:**
1. **Admin Panel Exposure** - Red team WILL brute force this
2. **SQL Injection** - OpenCart has history of SQLi vulnerabilities
3. **File Upload Exploits** - Can be used to upload web shells
4. **Default Install Files** - May still be present
5. **Database Access** - Credentials stored in `config.php`

**Immediate Actions on Game Start:**

1. **Login and Change Admin Password** (Minute 5-10)
   ```bash
   # Try default credentials at: http://172.20.242.30/admin
   # Navigate to: System → Users → Users
   # Change admin password to team password
   ```

2. **Run OpenCart Hardening Script** (Minute 5-10)
   ```bash
   ssh sysadmin@172.20.242.30
   cd /opt/ccdc26/linux-scripts/service-hardening
   sudo ./harden-opencart.sh
   ```

   This script will:
   - Remove `/install` directory (prevents reinstallation)
   - Rename `/admin` to `/admin_secure_XXXXX` (obfuscation)
   - Set secure file permissions
   - Install fail2ban for brute force protection
   - Enable Apache security headers

3. **Remove Suspicious Files** (Minute 8-10)
   ```bash
   # Remove malware-related script
   sudo rm /home/sysadmin/install-ssh-req.sh
   
   # Secure OpenCart source files
   sudo mkdir -p /root/backup
   sudo mv /home/sysadmin/opencart-master /root/backup/
   sudo mv /home/sysadmin/master.zip /root/backup/
   ```

4. **Change Database Password** (Minute 10-15)
   ```bash
   # Find DB credentials
   sudo grep "DB_" /var/www/html/config.php
   
   # Change password in MySQL (database name: opencart)
   sudo mysql -u root -p opencart
   ALTER USER 'opencart_user'@'localhost' IDENTIFIED BY 'NewPassword!';
   FLUSH PRIVILEGES;
   EXIT;
   
   # Update config.php with new password
   sudo nano /var/www/html/config.php
   # Update: define('DB_PASSWORD', 'NewPassword!');
   ```

5. **Monitor for Attacks** (Continuous)
   ```bash
   # Watch admin login attempts
   sudo tail -f /var/log/apache2/access.log | grep -i "admin"
   
   # Check for SQLi attempts
   sudo grep -iE "union.*select|concat\(" /var/log/apache2/access.log
   
   # Check for brute force (count POST requests to admin/login)
   sudo grep "POST.*admin.*login" /var/log/apache2/access.log | wc -l
   ```

**Documentation Created:**
- Full hardening guide: `APPLICATION-FINDINGS.md`
- Automated hardening script: `linux-scripts/service-hardening/harden-opencart.sh`
- Quick reference card: `OPENCART-QUICKREF.md`
- Suspicious files investigation script: `linux-scripts/emergency/investigate-ecom-suspicious-files.sh`

---

## 🌐 NETWORK ROUTING

### 8. VyOS Routing Configuration

**Status:** ✓ WORKING

The VyOS router is properly routing between subnets:
- `172.20.240.0/24` (Windows) → via `172.16.102.254` (Cisco FTD)
- `172.20.242.0/24` (Linux) → via `172.16.101.254` (Palo Alto)

**Verified with:** `show ip route`

However, **ping from Linux to Windows currently fails**:
- ICMP from 172.20.242.38 to 172.20.240.100 = 100% packet loss

**Possible Causes:**
1. Cisco FTD firewall rules blocking ICMP/WinRM from Linux subnet
2. Windows Firewall blocking from remote subnets
3. VyOS firewall rules (check with `show firewall`)

**Actions:**
- Check VyOS firewall: `show firewall`
- Check Cisco FTD rules via Web UI from Win11 Workstation
- Ensure Windows Firewall allows traffic from 172.20.242.0/24

---

## 🔑 PASSWORD INVENTORY

### Current Working Credentials

**Linux Machines:**

| Machine | IP | User | Password | Status |
|---------|-----|------|----------|--------|
| Ubuntu Ecom | 172.20.242.30 | sysadmin | changeme | ✓ Verified |
| Fedora Webmail | 172.20.242.40 | sysadmin | changeme | ✓ Verified |
| Splunk | 172.20.242.20 | sysadmin | changemenow | ✓ Verified (SSH) |
| Splunk | 172.20.242.20 | root | changemenow | ✓ Verified (console) |
| Ubuntu Wks | 172.20.242.38 | sysadmin | changeme | ✓ Verified |
| Palo Alto | 172.16.101.254 | sysadmin | changeme | ✓ Verified (Ubuntu Wks) |
| Cisco FTD | 172.20.240.200 | sysadmin | changeme | ✓ Verified (Palo Alto) |

**Windows Machines:**

| Machine | IP | User | Password | Status |
|---------|-----|------|----------|--------|
| Win11 Wks | 172.20.240.100 | userone | !Password123 | ✓ Verified |
| Win11 Wks | 172.20.240.100 | administrator | !Password123 | Not tested |
| AD/DNS 2019 | 172.20.240.102 | administrator | !Password123 | Not tested |
| Web 2019 | 172.20.240.101 | administrator | !Password123 | Not tested |
| FTP 2022 | 172.20.240.104 | administrator | !Password123 | Not tested |

**Network Devices:**

| Device | IP | Access | User | Password | Status |
|--------|-----|--------|------|----------|--------|
| VyOS | 172.16.101.1 | SSH | vyos | changeme | ✓ Verified |

**Issues to Resolve:**
1. Splunk SSH password in inventory is incorrect (uses `changemenow`, not `changeme`)
2. VyOS SSH password in inventory may need verification
3. Windows passwords not tested via WinRM yet

**Updated inventory.ini needed:**
```ini
[linux]
ubuntu-wks ansible_host=172.20.242.38 ansible_user=sysadmin ansible_password=changeme
ecom ansible_host=172.20.242.30 ansible_user=sysadmin ansible_password=changeme
webmail ansible_host=172.20.242.40 ansible_user=sysadmin ansible_password=changeme
paloalto ansible_host=172.16.101.254 ansible_user=sysadmin ansible_password=changeme
cisco-ftd ansible_host=172.20.240.200 ansible_user=sysadmin ansible_password=changeme
splunk ansible_host=172.20.242.20 ansible_user=sysadmin ansible_password=changemenow

[windows]
win11-wks ansible_host=172.20.240.100 ansible_user=userone ansible_password=!Password123 ansible_connection=winrm ansible_winrm_transport=basic ansible_port=5985
```

---

## 📋 PRE-GAME SETUP CHECKLIST

### Before Competition Starts

**On Ansible Controller (Ubuntu Workstation):**

- [ ] Install dependencies:
  ```bash
  sudo apt update
  sudo apt install -y git python3-pip sshpass
  pip3 install ansible pywinrm
  ansible-galaxy collection install ansible.windows
  ```

- [ ] Clone/update toolkit:
  ```bash
  cd /opt
  git clone <your-repo-url> ccdc26
  # OR
  cd /opt/ccdc26 && git pull
  ```

- [ ] Verify inventory.ini has correct passwords
- [ ] Disable host key checking:
  ```bash
  export ANSIBLE_HOST_KEY_CHECKING=False
  echo "export ANSIBLE_HOST_KEY_CHECKING=False" >> ~/.bashrc
  ```

**On Each Windows Machine:**

- [ ] Enable WinRM (run `Setup-WinRM-Ansible.ps1`)
- [ ] Verify WinRM is listening: `Get-Service WinRM`
- [ ] Test firewall allows port 5985 from 172.20.242.0/24
- [ ] Copy toolkit to `C:\ccdc26`

**Test Connectivity:**

- [ ] Test Linux machines: `ansible linux -i ansible/inventory.ini -m ping`
- [ ] Test Windows machines: `ansible windows -i ansible/inventory.ini -m win_ping`

---

## 🚀 GAME START PRIORITY ORDER

### Minute 0-2: MALWARE REMOVAL (CRITICAL)

**Run on ALL Linux machines simultaneously** (use `deploy.sh` Option 2 or manually via SSH):

```bash
# Create quick removal script
cat > /tmp/remove_malware.sh << 'EOF'
#!/bin/bash
systemctl stop startup_check.service 2>/dev/null
systemctl disable startup_check.service 2>/dev/null
rm -f /etc/startup_check.py
rm -f /etc/systemd/system/startup_check.service
rm -f /usr/share/startup_check-installer.sh
rm -f /etc/config.txt
rm -f /var/log/startup_check.log
find /home -name "authorized_keys" -delete
find /root -name "authorized_keys" -delete
systemctl daemon-reload
echo "Malware removed"
EOF

chmod +x /tmp/remove_malware.sh
sudo /tmp/remove_malware.sh
```

**Via Ansible (if connectivity working):**
```bash
ansible linux -i ansible/inventory.ini -b -m shell -a "systemctl stop startup_check.service; systemctl disable startup_check.service; rm -f /etc/startup_check.py /etc/systemd/system/startup_check.service /usr/share/startup_check-installer.sh /etc/config.txt; systemctl daemon-reload"
```

### Minute 2-5: PASSWORD CHANGES

**Change ALL passwords immediately:**

```bash
cd /opt/ccdc26
sudo ./deploy.sh
# Select: 2 (Ansible) → 3 (Password Reset + Kick Sessions)
```

### Minute 5-10: QUICK HARDENING

**Linux (via Ansible):**
```bash
sudo ./deploy.sh
# Select: 2 (Ansible) → 4 (Deploy Hardening) → 2 (Run scripts)
```

**Windows (on each machine):**
```powershell
cd C:\ccdc26\windows-scripts
.\hardening\Full-Harden.ps1 -q

# On Domain Controller only:
.\hardening\AD-Harden.ps1 -q
```

### Minute 10-15: MONITORING SETUP

**Deploy Wazuh/Splunk:**
```bash
sudo ./deploy.sh
# Select: 2 (Ansible) → 5 (Deploy Wazuh Agents)
# Select: 2 (Ansible) → 6 (Deploy Splunk Forwarders)
```

### Minute 15+: CONTINUOUS MONITORING

- [ ] Start real-time monitoring (Option 3 → 6)
- [ ] Hunt for new persistence mechanisms (Option 3 → 7)
- [ ] Monitor Splunk for anomalies
- [ ] Respond to injects

---

## 🔍 ONGOING MONITORING TASKS

### Every 10 Minutes

- [ ] Check for startup_check.service reappearance:
  ```bash
  systemctl status startup_check.service
  ls -la /etc/startup_check.py
  ```

- [ ] Check for new UID 0 accounts:
  ```bash
  awk -F: '$3 == 0 {print}' /etc/passwd | grep -v "^root:"
  ```

- [ ] Check for new SSH keys:
  ```bash
  find /home -name "authorized_keys" -mmin -10
  ```

### Every 30 Minutes

- [ ] Review Splunk dashboard for anomalies
- [ ] Check active SSH sessions: `w`
- [ ] Review auth logs: `sudo tail -100 /var/log/auth.log`

---

## 📞 REFERENCE INFORMATION

### Key IPs

| Purpose | IP | Access From |
|---------|-----|-------------|
| Ansible Controller | 172.20.242.38 | Ubuntu Wks |
| Splunk Server | 172.20.242.20 | All machines |
| Palo Alto Firewall | 172.16.101.254 | Ubuntu Wks (HTTPS) |
| Cisco FTD Firewall | 172.20.240.200 | Win11 Wks (HTTPS) |
| VyOS Router | 172.16.101.1 | Any (SSH) |

### Useful Commands

**Check if malware is running:**
```bash
ps aux | grep startup_check
systemctl list-units | grep startup
journalctl -u startup_check.service --no-pager | tail -20
```

**Find all Python scripts in /etc:**
```bash
find /etc -name "*.py" -type f
```

**Find all systemd services not from packages:**
```bash
systemctl list-unit-files --type=service | grep -v "@"
```

---

## ❓ QUESTIONS TO RESOLVE

### Before Game Start

1. **Do we have access to AD/DNS, Web 2019, and FTP 2022 servers?**
   - Need to verify Windows admin passwords
   - Need to enable WinRM on these machines
   - Currently only have access to Win11 Workstation

2. **What's the IP at 172.20.242.254?**
   - Listed in malware config.txt
   - We can ping it from Ubuntu workstation
   - Unknown device (investigate further)

3. **Is the startup_check malware a red team backdoor or pre-configured vuln?**
   - If pre-configured: safe to remove immediately
   - If red team: may reappear, need continuous monitoring
   - Research suggests CCDC doesn't typically pre-plant active malware

4. **Why can't we ping Windows machines from Linux?**
   - Routing works (VyOS confirmed)
   - Likely firewall issue on Cisco FTD or Windows Firewall
   - Need to investigate before WinRM will work

---

## 📝 NOTES FROM SESSION

- **Ansible Python module error:** Fixed by ensuring Python 3 is installed on target machines
- **Ubuntu UID 0 accounts:** Multiple suspicious accounts found in user enumeration
- **VyOS routing:** Confirmed working with `show ip route`
- **Windows WinRM:** Service was stopped by default, now enabled on Win11 Workstation
- **SSH passwords:** Some inconsistencies in inventory.ini vs actual passwords

---

## ✅ COMPLETED DURING EARLY ACCESS

- [x] Discovered and analyzed startup_check malware
- [x] Verified Linux machine credentials (Ubuntu Wks, Ecom, Webmail, Palo Alto, Cisco FTD)
- [x] Fixed Ansible sshpass dependency issue
- [x] Identified SSH authorized_keys backdoor
- [x] Found UID 0 account vulnerabilities
- [x] Enabled WinRM on Windows 11 Workstation
- [x] Created WinRM setup script for Windows machines
- [x] Verified VyOS routing configuration
- [x] Updated inventory.ini with correct passwords
- [x] Ran linuxcheck.sh on multiple machines
- [x] Enumerated users on Ubuntu Workstation

---

## 🎯 TOP PRIORITIES FOR GAME START

1. **REMOVE MALWARE** - startup_check.service on all Linux machines
2. **REMOVE SSH KEYS** - authorized_keys files on all machines
3. **CHANGE ALL PASSWORDS** - immediately after malware removal
4. **VERIFY UID 0 ACCOUNTS** - only root should have UID 0
5. **ENABLE WINDOWS WINRM** - for Ansible management (if not done pre-game)

---

**Last Updated:** January 21, 2026  
**Next Review:** January 24, 2026 (Game Day)

**Good luck, Team 2! 🎯🔒**
