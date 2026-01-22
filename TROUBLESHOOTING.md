# CCDC26 Troubleshooting Guide

Common issues and solutions for the CCDC26 defense toolkit.

## Table of Contents

1. [Network Connectivity Issues](#network-connectivity-issues)
2. [Ansible Connection Problems](#ansible-connection-problems)
3. [Wazuh Deployment Issues](#wazuh-deployment-issues)
4. [Windows WinRM Issues](#windows-winrm-issues)
5. [OS Detection Problems](#os-detection-problems)

---

## Network Connectivity Issues

### Problem: Linux hosts cannot reach Windows hosts

**Symptoms**:
- Ping from Linux to Windows fails
- Ansible cannot connect to Windows hosts
- `ansible windows -i inventory.ini -m win_ping` fails

**Root Causes**:
1. Cisco FTD firewall blocking traffic from Linux subnet (172.20.242.0/24) to Windows subnet (172.20.240.0/24)
2. Windows Firewall not configured to allow Linux subnet
3. WinRM not enabled on Windows hosts

**Solutions**:

1. **Configure Windows Firewall** (on each Windows host):
   ```powershell
   # Run as Administrator:
   cd C:\ccdc26\windows-scripts
   .\Setup-WinRM-Ansible.ps1
   ```
   This script:
   - Enables WinRM service
   - Configures firewall to allow Linux subnet (172.20.242.0/24)
   - Tests connectivity

2. **Configure Cisco FTD Firewall** (manual step):
   - Access FTD web interface: https://172.20.240.200 (from Windows host)
   - Create rule allowing:
     - Source: 172.20.242.0/24 (Linux subnet)
     - Destination: 172.20.240.0/24 (Windows subnet)
     - Service: TCP 5985 (WinRM), ICMP
   - Apply and commit changes

3. **Test connectivity**:
   ```bash
   # From Linux host:
   ping 172.20.240.100  # Should succeed
   nc -zv 172.20.240.100 5985  # Should show port open
   
   # From Ansible controller:
   ansible-playbook -i ansible/inventory.ini ansible/test-network-connectivity.yml
   ```

### Problem: Windows hosts cannot reach Linux hosts

**Symptoms**:
- Ping from Windows to Linux fails
- Windows cannot SSH to Linux hosts

**Solutions**:
1. Check Palo Alto firewall rules (allow Windows subnet to Linux subnet)
2. Verify Linux firewall allows Windows subnet:
   ```bash
   # On Linux host:
   sudo ufw allow from 172.20.240.0/24
   # Or for iptables:
   sudo iptables -A INPUT -s 172.20.240.0/24 -j ACCEPT
   ```

---

## Ansible Connection Problems

### Problem: "Host key checking failed"

**Solution**:
```bash
# Option 1: Disable globally (CCDC acceptable)
export ANSIBLE_HOST_KEY_CHECKING=False

# Option 2: Configure in ansible.cfg (already set)
# See ansible/ansible.cfg

# Option 3: Accept keys manually
ssh sysadmin@172.20.242.30  # Type 'yes' when prompted
```

### Problem: "Missing sudo password"

**Symptoms**:
- Ansible fails with "Missing sudo password" error
- Some hosts work, others don't

**Solutions**:
1. **Check inventory.ini** - Ensure `ansible_become_pass` is set per-host:
   ```ini
   ecom ansible_host=172.20.242.30 ansible_user=sysadmin ansible_password=changeme ansible_become_pass=changeme
   ```

2. **Use prompt mode** (in deploy.sh):
   - Select option 2 (Ansible Control Panel)
   - Select option 9 (Change auth mode)
   - Choose option 1 (Prompt for passwords)

3. **Verify sudo configuration** on target host:
   ```bash
   # On target Linux host:
   sudo -l  # Should show NOPASSWD or require password
   ```

### Problem: "Module not found" or Python interpreter errors

**Symptoms**:
- Ansible fails with "The module was not found" or "No module named..."
- Oracle Linux or Fedora hosts fail

**Solutions**:
1. **Verify Python 3 is installed**:
   ```bash
   # On target host:
   python3 --version
   which python3
   ```

2. **Set Python interpreter in inventory.ini**:
   ```ini
   [linux:vars]
   ansible_python_interpreter=/usr/bin/python3
   # Or for Oracle Linux:
   ansible_python_interpreter=/usr/libexec/platform-python
   ```

3. **The playbook now auto-detects Python** - this should be handled automatically.

### Problem: WinRM connection timeout

**Symptoms**:
- Ansible hangs when connecting to Windows hosts
- Timeout errors after 30+ seconds

**Solutions**:
1. **Check WinRM service** (on Windows host):
   ```powershell
   Get-Service WinRM  # Should be Running
   Test-WSMan localhost  # Should succeed
   ```

2. **Verify firewall rules**:
   ```powershell
   Get-NetFirewallRule -Name "*WinRM*" | Where-Object { $_.Enabled -eq $true }
   ```

3. **Increase timeout in ansible.cfg** (already configured):
   ```ini
   [winrm]
   connection_timeout = 60
   operation_timeout = 60
   ```

4. **Test connectivity manually**:
   ```powershell
   # From Windows host:
   Test-NetConnection -ComputerName <linux-ip> -Port 5985
   ```

---

## Wazuh Deployment Issues

### Problem: Wazuh agent cannot connect to manager

**Symptoms**:
- Agent installed but shows "Disconnected" status
- Agent registration fails
- No events in Wazuh dashboard

**Solutions**:
1. **Test connectivity** (on agent host):
   ```bash
   # Linux:
   nc -zv <manager-ip> 1514
   nc -zv <manager-ip> 1515
   
   # Windows:
   Test-NetConnection -ComputerName <manager-ip> -Port 1514
   ```

2. **Check firewall rules**:
   - Linux: Allow outbound TCP 1514, 1515
   - Windows: Allow outbound TCP 1514, 1515
   - Manager: Allow inbound TCP 1514, 1515 from agent subnets

3. **Verify manager is running**:
   ```bash
   # On Wazuh manager:
   docker ps  # Should show wazuh-manager container
   docker logs wazuh-manager  # Check for errors
   ```

4. **Check agent configuration**:
   ```bash
   # Linux:
   cat /var/ossec/etc/ossec.conf | grep -A3 "<server>"
   
   # Windows:
   Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "server"
   ```

5. **Manual agent registration** (if auto-registration fails):
   ```bash
   # On manager:
   /var/ossec/bin/manage_agents
   # Follow prompts to add agent
   
   # On agent:
   /var/ossec/bin/manage_agents -i <key-from-manager>
   ```

### Problem: Wazuh Docker containers use too much memory

**Symptoms**:
- VMs become slow or unresponsive
- Docker containers are killed (OOM)
- `docker stats` shows high memory usage

**Solutions**:
1. **Use lightweight compose file**:
   ```bash
   cd wazuh-content/docker
   docker compose -f docker-compose.lightweight.yml up -d
   ```
   This uses only the manager (no indexer/dashboard) - requires ~1GB RAM.

2. **Reduce JVM heap size** (already done in updated docker-compose.yml):
   - Indexer: Reduced from 1g to 512m-1g
   - Resource limits added

3. **Monitor resource usage**:
   ```bash
   docker stats
   free -h  # Check available memory
   ```

### Problem: Wazuh agent installation fails on Oracle Linux

**Symptoms**:
- Playbook fails with "No package matching 'wazuh-agent'"
- OS detection errors

**Solutions**:
1. **The playbook now handles Oracle Linux** - it's detected as RHEL family and uses yum.

2. **Manual installation** (if playbook fails):
   ```bash
   # On Oracle Linux host:
   sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
   sudo yum install -y wazuh-agent
   ```

---

## Windows WinRM Issues

### Problem: WinRM service not running

**Symptoms**:
- Ansible cannot connect to Windows hosts
- `ansible windows -i inventory.ini -m win_ping` fails

**Solutions**:
1. **Run setup script**:
   ```powershell
   # As Administrator:
   cd C:\ccdc26\windows-scripts
   .\Setup-WinRM-Ansible.ps1
   ```

2. **Manual setup**:
   ```powershell
   winrm quickconfig -y
   Enable-PSRemoting -Force
   Set-Service WinRM -StartupType Automatic
   Start-Service WinRM
   ```

3. **Verify service**:
   ```powershell
   Get-Service WinRM  # Should show Running
   Test-WSMan localhost  # Should succeed
   ```

### Problem: WinRM authentication fails

**Symptoms**:
- Ansible connects but authentication fails
- "Authentication failure" errors

**Solutions**:
1. **Check inventory.ini credentials**:
   ```ini
   [windows]
   ad-dns ansible_host=172.20.240.102 ansible_user=administrator ansible_password=!Password123
   ```

2. **Verify WinRM transport** (in inventory.ini):
   ```ini
   [windows:vars]
   ansible_connection=winrm
   ansible_winrm_transport=ntlm  # or basic, credssp
   ```

3. **Test authentication manually**:
   ```powershell
   # From Linux (if pywinrm installed):
   python3 -c "import winrm; s = winrm.Session('172.20.240.102', auth=('administrator', '!Password123')); print(s.run_cmd('hostname').stdout)"
   ```

---

## OS Detection Problems

### Problem: Ansible cannot detect OS correctly

**Symptoms**:
- Playbook fails with "OS not supported"
- Oracle Linux detected as unknown
- Fedora uses wrong package manager

**Solutions**:
1. **The playbook now has improved OS detection** - it handles:
   - Oracle Linux (detected as RHEL family)
   - Fedora (uses dnf instead of yum)
   - Python interpreter auto-detection

2. **Manual OS detection**:
   ```bash
   ansible all -i inventory.ini -m setup -a "filter=ansible_distribution*"
   ```

3. **Override in inventory.ini** (if needed):
   ```ini
   splunk ansible_host=172.20.242.20 ansible_user=sysadmin ansible_python_interpreter=/usr/libexec/platform-python
   ```

---

## Quick Diagnostic Commands

### Test Ansible connectivity:
```bash
# Test all hosts:
ansible all -i ansible/inventory.ini -m ping

# Test Windows only:
ansible windows -i ansible/inventory.ini -m win_ping

# Test Linux only:
ansible linux -i ansible/inventory.ini -m ping
```

### Test network connectivity:
```bash
# Run comprehensive network test:
ansible-playbook -i ansible/inventory.ini ansible/test-network-connectivity.yml
```

### Check Wazuh status:
```bash
# On manager:
docker ps | grep wazuh
docker logs wazuh-manager --tail 50

# On agent (Linux):
sudo systemctl status wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log

# On agent (Windows):
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```

### Check firewall rules:
```bash
# Linux (iptables):
sudo iptables -L -n -v

# Linux (ufw):
sudo ufw status verbose

# Windows:
Get-NetFirewallRule -Name "*WinRM*" | Format-Table Name, Enabled, Direction
```

---

## Getting Help

If issues persist:

1. Check logs:
   - Ansible: Add `-v` or `-vvv` for verbose output
   - Wazuh: Check agent and manager logs
   - System: Check `/var/log/` (Linux) or Event Viewer (Windows)

2. Run diagnostics:
   ```bash
   ansible-playbook -i ansible/inventory.ini ansible/test-network-connectivity.yml
   ansible all -i ansible/inventory.ini -m setup
   ```

3. Review documentation:
   - [README.md](README.md) - Main documentation
   - [ansible/README.md](ansible/README.md) - Ansible-specific docs
   - [wazuh-content/README.md](wazuh-content/README.md) - Wazuh docs
