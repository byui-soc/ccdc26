# MEMORANDUM

| | |
|---|---|
| **TO:** | Management / IT Security Team |
| **FROM:** | Linux Systems Administration Team |
| **DATE:** | January 24, 2026 |
| **RE:** | Linux Startup Files and Scripts Security Audit |

---

## Executive Summary

This memo presents a comprehensive checklist of startup files and scripts that should be reviewed for security abnormalities on Linux systems. It includes an explanation of systemd vs. non-systemd init systems, audit results for each Linux server in our environment, and documentation of any suspicious items discovered and actions taken.

---

## Systemd vs. Non-Systemd Linux Versions

### What is an Init System?

The init system is the first process started by the Linux kernel (PID 1) and is responsible for starting all other system services and processes during boot.

### Systemd (Modern Linux)

**Systemd** is the modern init system used by most current Linux distributions.

| Aspect | Description |
|--------|-------------|
| **Introduced** | 2010, widely adopted by 2015 |
| **Service Files** | `.service` files in `/etc/systemd/system/` and `/lib/systemd/system/` |
| **Management** | `systemctl` command |
| **Parallelization** | Starts services in parallel for faster boot |
| **Dependencies** | Explicit dependency management between services |
| **Logging** | Integrated journal (`journalctl`) |

**Distributions using systemd:**
- Ubuntu 15.04+ (including 24.04)
- Fedora 15+ (including Fedora 42)
- RHEL/CentOS 7+
- Debian 8+
- Oracle Linux 7+

### Non-Systemd (Legacy Init Systems)

**SysVinit** and **Upstart** were used by older Linux distributions.

| Aspect | SysVinit | Upstart |
|--------|----------|---------|
| **Service Scripts** | `/etc/init.d/` shell scripts | `/etc/init/` .conf files |
| **Management** | `service` command, `update-rc.d` | `initctl` command |
| **Startup Order** | Runlevel-based (rc0.d - rc6.d) | Event-based |
| **Boot Speed** | Sequential (slower) | Partially parallel |

**Distributions that used non-systemd:**
- Ubuntu 6.10 - 14.10 (Upstart)
- RHEL/CentOS 5-6 (SysVinit)
- Debian 7 and earlier (SysVinit)

### Key Differences for Security Auditing

| Location | Systemd | SysVinit/Upstart |
|----------|---------|------------------|
| Service definitions | `/etc/systemd/system/` | `/etc/init.d/`, `/etc/init/` |
| Enable/disable | `systemctl enable/disable` | `update-rc.d`, `chkconfig` |
| Startup scripts | `/etc/systemd/system/*.service` | `/etc/rc.local`, `/etc/rc?.d/` |
| User services | `~/.config/systemd/user/` | N/A |
| Timers (cron-like) | `/etc/systemd/system/*.timer` | `/etc/cron.*` only |

---

## Startup Files and Scripts Checklist

### Systemd-Based Systems

#### Service Files (HIGH PRIORITY)

| Location | What to Check | Risk Level |
|----------|---------------|------------|
| `/etc/systemd/system/` | Custom service files | **CRITICAL** |
| `/etc/systemd/system/*.wants/` | Enabled service symlinks | **HIGH** |
| `/lib/systemd/system/` | Package-installed services | MEDIUM |
| `/run/systemd/system/` | Runtime-generated services | **HIGH** |
| `~/.config/systemd/user/` | User-level services | **HIGH** |

**Commands to audit:**
```bash
# List all enabled services
systemctl list-unit-files --state=enabled

# List all running services
systemctl list-units --type=service --state=running

# List custom services (not from packages)
ls -la /etc/systemd/system/*.service 2>/dev/null

# Check for recently modified service files
find /etc/systemd/system -name "*.service" -mtime -7 -ls

# List timers (scheduled tasks)
systemctl list-timers --all
```

#### Timer Files (Scheduled Tasks)

| Location | Purpose |
|----------|---------|
| `/etc/systemd/system/*.timer` | Custom scheduled tasks |
| `/lib/systemd/system/*.timer` | Package timers |

### Cron Jobs (All Systems)

| Location | What to Check | Risk Level |
|----------|---------------|------------|
| `/etc/crontab` | System crontab | **CRITICAL** |
| `/etc/cron.d/` | Package/custom cron jobs | **CRITICAL** |
| `/etc/cron.daily/` | Daily scripts | **HIGH** |
| `/etc/cron.hourly/` | Hourly scripts | **HIGH** |
| `/etc/cron.weekly/` | Weekly scripts | MEDIUM |
| `/etc/cron.monthly/` | Monthly scripts | MEDIUM |
| `/var/spool/cron/crontabs/` | User crontabs | **CRITICAL** |

**Commands to audit:**
```bash
# View system crontab
cat /etc/crontab

# List all cron.d entries
ls -la /etc/cron.d/

# View all user crontabs
for user in $(cut -f1 -d: /etc/passwd); do 
    echo "=== $user ===" 
    crontab -l -u $user 2>/dev/null
done

# Find recently modified cron files
find /etc/cron* -type f -mtime -7 -ls
```

### Shell Profile Scripts (Login Execution)

| Location | When Executed | Risk Level |
|----------|---------------|------------|
| `/etc/profile` | All login shells | **CRITICAL** |
| `/etc/profile.d/*.sh` | All login shells | **CRITICAL** |
| `/etc/bash.bashrc` | All bash shells | **HIGH** |
| `/etc/bashrc` | All bash shells (RHEL) | **HIGH** |
| `~/.bashrc` | User bash shells | **HIGH** |
| `~/.profile` | User login shells | **HIGH** |
| `~/.bash_profile` | User bash login | **HIGH** |
| `~/.bash_login` | User bash login | **HIGH** |
| `/root/.bashrc` | Root shell | **CRITICAL** |
| `/root/.profile` | Root login | **CRITICAL** |

**Commands to audit:**
```bash
# Check for suspicious commands in profile scripts
grep -r "curl\|wget\|base64\|eval\|nc\|ncat\|python\|perl\|ruby" /etc/profile /etc/profile.d/ /etc/bash* 2>/dev/null

# Check root's shell configs
cat /root/.bashrc /root/.profile /root/.bash_profile 2>/dev/null
```

### Init Scripts (Legacy + Compatibility)

| Location | Purpose | Risk Level |
|----------|---------|------------|
| `/etc/init.d/` | SysVinit service scripts | **HIGH** |
| `/etc/rc.local` | Legacy startup script | **CRITICAL** |
| `/etc/rc?.d/` | Runlevel symlinks | **HIGH** |

**Commands to audit:**
```bash
# Check rc.local
cat /etc/rc.local 2>/dev/null

# List init.d scripts
ls -la /etc/init.d/

# Find non-package init scripts
find /etc/init.d -type f -exec rpm -qf {} \; 2>/dev/null | grep "not owned"
```

### Kernel Modules and Boot

| Location | Purpose | Risk Level |
|----------|---------|------------|
| `/etc/modules` | Modules loaded at boot | **HIGH** |
| `/etc/modules-load.d/` | Systemd module loading | **HIGH** |
| `/etc/modprobe.d/` | Module parameters | MEDIUM |
| `/boot/grub/grub.cfg` | Boot configuration | **CRITICAL** |

### Other Persistence Locations

| Location | Purpose | Risk Level |
|----------|---------|------------|
| `/etc/ld.so.preload` | Library preloading (ROOTKIT) | **CRITICAL** |
| `/etc/ld.so.conf.d/` | Library paths | **HIGH** |
| `/etc/ssh/sshrc` | SSH login script | **HIGH** |
| `/etc/pam.d/` | Authentication modules | **CRITICAL** |
| `~/.ssh/rc` | User SSH login script | **HIGH** |
| `~/.ssh/authorized_keys` | SSH key access | **CRITICAL** |

---

## Audit Tools Used

| Tool | Purpose | Command |
|------|---------|---------|
| **systemctl** | List and inspect systemd services | `systemctl list-unit-files` |
| **find** | Locate recently modified files | `find /etc -mtime -7` |
| **grep** | Search for suspicious patterns | `grep -r "pattern" /path` |
| **ls** | List files with timestamps | `ls -la` |
| **stat** | Detailed file timestamps | `stat filename` |
| **rpm -qf** / **dpkg -S** | Verify file ownership by packages | `rpm -qf /path/to/file` |
| **journalctl** | Review systemd logs | `journalctl -u servicename` |
| **ausearch** | Search audit logs | `ausearch -k audit_key` |
| **chkrootkit** | Rootkit detection | `chkrootkit` |
| **rkhunter** | Rootkit hunter | `rkhunter --check` |
| **Custom scripts** | integrity-baseline.sh, integrity-monitor.sh | File integrity monitoring |

---

## Server Audit Results

### Server 1: Ubuntu Ecom (172.20.242.30)

| Attribute | Value |
|-----------|-------|
| **Hostname** | czatelif |
| **OS Version** | Ubuntu Server 24.04.3 LTS |
| **Init System** | **Systemd** |
| **Kernel** | Linux 6.x |

#### Items Checked

| Location | Status | Findings |
|----------|--------|----------|
| `/etc/systemd/system/` | **SUSPICIOUS** | Found `startup-check.service` (malware) |
| `/etc/cron.d/` | Clean | No suspicious entries |
| `/etc/crontab` | Clean | Default configuration |
| `/etc/profile.d/` | Clean | No suspicious scripts |
| `/root/.bashrc` | Clean | No malicious additions |
| `/root/.ssh/authorized_keys` | **SUSPICIOUS** | Unknown SSH keys found |
| `/etc/rc.local` | Clean | Empty/disabled |
| `/etc/ld.so.preload` | Clean | Empty |

#### Abnormalities Found and Actions Taken

| Finding | Location | Action Taken |
|---------|----------|--------------|
| Malicious service | `/etc/systemd/system/startup-check.service` | **REMOVED** - Disabled and deleted |
| Malware script | `/etc/startup_check.py` | **REMOVED** - Deleted |
| Malware config | `/etc/config.txt` | **REMOVED** - Deleted |
| Paramiko library | pip3 packages | **REMOVED** - Uninstalled |
| Unknown SSH keys | `/root/.ssh/authorized_keys` | **REMOVED** - Cleaned |

---

### Server 2: Fedora Webmail (172.20.242.40)

| Attribute | Value |
|-----------|-------|
| **Hostname** | fedora-webmail |
| **OS Version** | Fedora 42 |
| **Init System** | **Systemd** |
| **Kernel** | Linux 6.x |

#### Items Checked

| Location | Status | Findings |
|----------|--------|----------|
| `/etc/systemd/system/` | **SUSPICIOUS** | Malicious service found |
| `/etc/cron.d/` | Clean | No suspicious entries |
| `/etc/crontab` | Clean | Default configuration |
| `/etc/profile.d/` | Clean | No suspicious scripts |
| `/root/.bashrc` | Clean | No malicious additions |
| `/root/.ssh/authorized_keys` | **SUSPICIOUS** | Unknown SSH keys found |
| `/etc/rc.local` | Clean | Not present |
| `/etc/ld.so.preload` | Clean | Empty |

#### Abnormalities Found and Actions Taken

| Finding | Location | Action Taken |
|---------|----------|--------------|
| Malicious service | `/etc/systemd/system/startup-check.service` | **REMOVED** - Disabled and deleted |
| Malware script | `/etc/startup_check.py` | **REMOVED** - Deleted |
| Malware config | `/etc/config.txt` | **REMOVED** - Deleted |
| Unknown SSH keys | `/root/.ssh/authorized_keys` | **REMOVED** - Cleaned |

---

### Server 3: Splunk (172.20.242.20)

| Attribute | Value |
|-----------|-------|
| **Hostname** | splunk |
| **OS Version** | Oracle Linux 9.2 |
| **Init System** | **Systemd** |
| **Kernel** | Linux 5.x |

#### Items Checked

| Location | Status | Findings |
|----------|--------|----------|
| `/etc/systemd/system/` | **SUSPICIOUS** | Malicious service found |
| `/etc/cron.d/` | Clean | No suspicious entries |
| `/etc/crontab` | Clean | Default configuration |
| `/etc/profile.d/` | Clean | No suspicious scripts |
| `/root/.bashrc` | Clean | No malicious additions |
| `/root/.ssh/authorized_keys` | **SUSPICIOUS** | Unknown SSH keys found |
| `/etc/rc.local` | Clean | Not present |
| `/etc/ld.so.preload` | Clean | Empty |

#### Abnormalities Found and Actions Taken

| Finding | Location | Action Taken |
|---------|----------|--------------|
| Malicious service | `/etc/systemd/system/startup-check.service` | **REMOVED** - Disabled and deleted |
| Malware script | `/etc/startup_check.py` | **REMOVED** - Deleted |
| Malware config | `/etc/config.txt` | **REMOVED** - Deleted |
| Unknown SSH keys | `/root/.ssh/authorized_keys` | **REMOVED** - Cleaned |

---

## Quick Audit Commands

Run these on each Linux server:

```bash
#!/bin/bash
# Quick Startup Audit Script

echo "=== SYSTEM INFO ==="
cat /etc/os-release | grep -E "^NAME|^VERSION"
ps -p 1 -o comm=  # Shows init system

echo ""
echo "=== SYSTEMD SERVICES (enabled) ==="
systemctl list-unit-files --state=enabled --type=service | grep -v "^UNIT"

echo ""
echo "=== CUSTOM SYSTEMD SERVICES ==="
ls -la /etc/systemd/system/*.service 2>/dev/null

echo ""
echo "=== CRON.D ENTRIES ==="
ls -la /etc/cron.d/

echo ""
echo "=== USER CRONTABS ==="
for user in $(cut -f1 -d: /etc/passwd); do 
    crontab -l -u $user 2>/dev/null && echo "(user: $user)"
done

echo ""
echo "=== PROFILE.D SCRIPTS ==="
ls -la /etc/profile.d/

echo ""
echo "=== RC.LOCAL ==="
cat /etc/rc.local 2>/dev/null || echo "(not present)"

echo ""
echo "=== LD.SO.PRELOAD ==="
cat /etc/ld.so.preload 2>/dev/null || echo "(empty or not present)"

echo ""
echo "=== ROOT SSH KEYS ==="
cat /root/.ssh/authorized_keys 2>/dev/null | wc -l
echo "keys found"

echo ""
echo "=== RECENTLY MODIFIED IN /etc (7 days) ==="
find /etc -type f -mtime -7 -name "*.service" -o -name "*.sh" 2>/dev/null | head -20
```

---

## Conclusion

All Linux servers in the environment use **systemd** as their init system. A comprehensive audit of startup files and scripts was conducted using the checklist above.

**Key findings:** Malicious persistence was discovered on **ALL THREE Linux servers**:

| Server | Malware Found | Status |
|--------|---------------|--------|
| Ubuntu Ecom (172.20.242.30) | startup-check.service, startup_check.py | **CLEANED** |
| Fedora Webmail (172.20.242.40) | startup-check.service, startup_check.py | **CLEANED** |
| Splunk (172.20.242.20) | startup-check.service, startup_check.py | **CLEANED** |

The malware was a Python-based SSH worm that used systemd for persistence. All instances have been removed including:
- Systemd service files
- Python malware scripts
- Configuration files with credentials
- Unauthorized SSH keys

All startup locations have been verified clean across the environment.

---

*Audit completed by Linux Systems Administration Team - January 24, 2026*
