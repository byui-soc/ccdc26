# MEMORANDUM

| | |
|---|---|
| **TO:** | Management / IT Security Team |
| **FROM:** | Linux Systems Administration Team |
| **DATE:** | January 24, 2026 |
| **RE:** | File Integrity Monitoring Scripts Implementation |

---

## Executive Summary

Two scripts have been developed to monitor key system and application files for modifications, additions, and deletions. These scripts work together to establish file baselines and continuously verify file integrity, alerting administrators via SYSLOG when changes are detected.

---

## AI Tool Disclosure

**AI Tool Used:** Claude (Anthropic)

**Instructions Provided to Generate Scripts:**

> "Create two bash scripts for file integrity monitoring:
> 
> Script 1 - Baseline Generator:
> - Accept a directory path as a parameter
> - Generate SHA256 hashes for all files in the directory
> - Store the database as a flat file within the monitored directory
> - Include file permissions, ownership, size, and modification time
> 
> Script 2 - Integrity Monitor:
> - Run periodically (designed for 5-minute cron intervals)
> - Compare current file states against baseline databases
> - Process multiple directories (each with its own baseline)
> - Alert via SYSLOG for: modified files, new files, deleted files
> - Provide both console and syslog output"

---

## Script 1: Baseline Generator

**Filename:** `integrity-baseline.sh`

**Purpose:** Creates a database of file hash signatures for a specified directory

**Location:** `/opt/ccdc-toolkit/linux-scripts/monitoring/integrity-baseline.sh`

### Code

```bash
#!/bin/bash
#=============================================================================
# INTEGRITY BASELINE GENERATOR
# 
# Purpose: Generate a database of file hash signatures for a given directory
# Usage:   ./integrity-baseline.sh /path/to/directory
# Output:  Creates .integrity_baseline.db in the target directory
#
# Generated with AI assistance (Claude) for CCDC file integrity monitoring
#=============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Database filename (stored in each monitored directory)
DB_FILENAME=".integrity_baseline.db"

#=============================================================================
# FUNCTIONS
#=============================================================================

usage() {
    echo "Usage: $0 <directory>"
    echo ""
    echo "Generates a baseline database of file hashes for the specified directory."
    echo "The database is stored as: <directory>/$DB_FILENAME"
    echo ""
    echo "Examples:"
    echo "  $0 /etc"
    echo "  $0 /var/www/html"
    echo "  $0 /home/user"
    exit 1
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

generate_baseline() {
    local target_dir="$1"
    local db_file="${target_dir}/${DB_FILENAME}"
    local temp_file=$(mktemp)
    local file_count=0
    
    log_info "Generating baseline for: $target_dir"
    log_info "Database file: $db_file"
    
    # Write header
    cat > "$temp_file" << EOF
# Integrity Baseline Database
# Directory: $target_dir
# Generated: $(date -Iseconds)
# Hostname: $(hostname)
# Format: HASH|PERMISSIONS|OWNER:GROUP|SIZE|MTIME|FILEPATH
EOF
    
    # Process all files in directory (excluding the database file itself)
    while IFS= read -r -d '' file; do
        # Skip the database file
        [[ "$file" == "$db_file" ]] && continue
        
        # Skip if not a regular file
        [[ ! -f "$file" ]] && continue
        
        # Get file attributes
        local hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        local perms=$(stat -c '%a' "$file" 2>/dev/null)
        local owner=$(stat -c '%U:%G' "$file" 2>/dev/null)
        local size=$(stat -c '%s' "$file" 2>/dev/null)
        local mtime=$(stat -c '%Y' "$file" 2>/dev/null)
        
        # Write to database
        echo "${hash}|${perms}|${owner}|${size}|${mtime}|${file}" >> "$temp_file"
        ((file_count++))
        
        # Progress indicator
        if ((file_count % 100 == 0)); then
            echo -ne "\r  Processed $file_count files..."
        fi
    done < <(find "$target_dir" -type f -print0 2>/dev/null)
    
    echo -ne "\r"
    
    # Move temp file to final location
    mv "$temp_file" "$db_file"
    chmod 600 "$db_file"
    
    log_info "Baseline complete: $file_count files recorded"
    log_info "Database saved to: $db_file"
}

#=============================================================================
# MAIN
#=============================================================================

# Check arguments
if [[ $# -ne 1 ]]; then
    usage
fi

TARGET_DIR="$1"

# Validate directory
if [[ ! -d "$TARGET_DIR" ]]; then
    log_error "Directory does not exist: $TARGET_DIR"
    exit 1
fi

# Convert to absolute path
TARGET_DIR=$(cd "$TARGET_DIR" && pwd)

# Check write permissions
if [[ ! -w "$TARGET_DIR" ]]; then
    log_error "Cannot write to directory: $TARGET_DIR"
    log_error "Run with sudo or check permissions"
    exit 1
fi

# Generate baseline
generate_baseline "$TARGET_DIR"

exit 0
```

### Usage

```bash
# Generate baseline for /etc directory
sudo ./integrity-baseline.sh /etc

# Generate baseline for web root
sudo ./integrity-baseline.sh /var/www/html

# Generate baseline for home directories
sudo ./integrity-baseline.sh /home
```

### Database Format

The database is stored as `.integrity_baseline.db` in each monitored directory:

```
# Integrity Baseline Database
# Directory: /etc
# Generated: 2026-01-24T10:30:00-05:00
# Hostname: webserver1
# Format: HASH|PERMISSIONS|OWNER:GROUP|SIZE|MTIME|FILEPATH
a1b2c3d4...|644|root:root|1234|1706012345|/etc/passwd
e5f6g7h8...|640|root:shadow|2048|1706012345|/etc/shadow
```

---

## Script 2: Integrity Monitor

**Filename:** `integrity-monitor.sh`

**Purpose:** Compare current files against baselines, alert on changes via SYSLOG

**Location:** `/opt/ccdc-toolkit/linux-scripts/monitoring/integrity-monitor.sh`

### Code

```bash
#!/bin/bash
#=============================================================================
# INTEGRITY MONITOR
# 
# Purpose: Compare current file states against baseline databases
#          Detect modified, new, and deleted files
#          Alert via SYSLOG for investigation
#
# Usage:   ./integrity-monitor.sh [directory1] [directory2] ...
#          ./integrity-monitor.sh --all (uses default critical directories)
#
# Designed to run every 5 minutes via cron
#
# Generated with AI assistance (Claude) for CCDC file integrity monitoring
#=============================================================================

set -uo pipefail

# Database filename (must match baseline generator)
DB_FILENAME=".integrity_baseline.db"

# Syslog facility and priority
SYSLOG_FACILITY="local0"
SYSLOG_PRIORITY="alert"
SYSLOG_TAG="integrity-monitor"

# Colors for console output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default critical directories to monitor
DEFAULT_DIRECTORIES=(
    "/etc"
    "/root"
    "/var/www"
    "/opt"
    "/usr/local/bin"
    "/home"
)

# [... full script continues - see repository for complete code ...]
```

### Usage

```bash
# Check specific directories
sudo ./integrity-monitor.sh /etc /var/www

# Check all default critical directories
sudo ./integrity-monitor.sh --all

# Quiet mode (syslog only, no console output)
sudo ./integrity-monitor.sh --all --quiet
```

---

## Monitored Directories and Importance

| Directory | Why Important |
|-----------|---------------|
| `/etc` | System configuration files - modifications can disable security controls, add backdoor users, or change service behavior |
| `/root` | Root user's home directory - contains admin scripts, SSH keys, shell configs that attackers target for persistence |
| `/var/www` | Web application files - web shells, defacement, and malicious code injection occur here |
| `/opt` | Third-party applications - attackers may modify installed software or add malicious packages |
| `/usr/local/bin` | Custom executables - trojanized binaries and malicious scripts are often placed here |
| `/home` | User home directories - SSH keys, user scripts, and personal configs can be weaponized |

### Critical Files Within These Directories

| File/Pattern | Risk |
|--------------|------|
| `/etc/passwd`, `/etc/shadow` | Rogue user accounts, password tampering |
| `/etc/sudoers`, `/etc/sudoers.d/*` | Privilege escalation via sudo rules |
| `/etc/ssh/sshd_config` | Weakened SSH security, backdoor access |
| `/etc/cron.*/*` | Attacker persistence via scheduled tasks |
| `/etc/systemd/system/*` | Malicious services for persistence |
| `/root/.ssh/authorized_keys` | Unauthorized SSH key access |
| `/var/www/html/*.php` | Web shells and malicious scripts |

---

## Cron Configuration

To run the monitor every 5 minutes, add the following cron job:

**File:** `/etc/cron.d/integrity-monitor`

```cron
# File Integrity Monitor - runs every 5 minutes
*/5 * * * * root /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-monitor.sh --all --quiet
```

**Manual installation:**
```bash
echo '*/5 * * * * root /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-monitor.sh --all --quiet' | sudo tee /etc/cron.d/integrity-monitor
sudo chmod 644 /etc/cron.d/integrity-monitor
```

---

## SYSLOG Alerts

All integrity violations are logged via syslog with:

- **Facility:** local0
- **Priority:** alert
- **Tag:** integrity-monitor

### Alert Types

| Alert | Example Message |
|-------|-----------------|
| Modified File | `MODIFIED FILE: /etc/passwd (hash changed)` |
| Permission Change | `PERMISSION CHANGE: /etc/shadow (640 -> 644)` |
| Owner Change | `OWNER CHANGE: /etc/cron.d/backup (root:root -> user:user)` |
| New File | `NEW FILE: /var/www/html/shell.php (not in baseline)` |
| Deleted File | `DELETED FILE: /etc/sudoers.d/admin (missing from system)` |

### Viewing Alerts

```bash
# View recent integrity alerts
sudo grep "integrity-monitor" /var/log/syslog | tail -50

# Or on RHEL/CentOS
sudo grep "integrity-monitor" /var/log/messages | tail -50

# Real-time monitoring
sudo tail -f /var/log/syslog | grep "integrity-monitor"
```

---

## Deployment Steps

### 1. Deploy Scripts to Each Server

```bash
# Copy scripts to target location
sudo cp integrity-baseline.sh /opt/ccdc-toolkit/linux-scripts/monitoring/
sudo cp integrity-monitor.sh /opt/ccdc-toolkit/linux-scripts/monitoring/
sudo chmod +x /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-*.sh
```

### 2. Generate Initial Baselines

```bash
# Generate baselines for critical directories
sudo /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-baseline.sh /etc
sudo /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-baseline.sh /root
sudo /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-baseline.sh /var/www
sudo /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-baseline.sh /home
```

### 3. Configure Cron Job

```bash
echo '*/5 * * * * root /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-monitor.sh --all --quiet' | sudo tee /etc/cron.d/integrity-monitor
```

### 4. Verify Operation

```bash
# Run manual check
sudo /opt/ccdc-toolkit/linux-scripts/monitoring/integrity-monitor.sh --all

# Verify cron is running
sudo grep "integrity-monitor" /var/log/syslog
```

---

## Evidence of Functional Script

### Screenshot: Baseline Generation
<!-- INSERT SCREENSHOT: sudo ./integrity-baseline.sh /etc -->

### Screenshot: Integrity Check (Clean)
<!-- INSERT SCREENSHOT: sudo ./integrity-monitor.sh --all -->

### Screenshot: Integrity Check (Changes Detected)
<!-- INSERT SCREENSHOT: After modifying a file, run check again -->

### Screenshot: SYSLOG Alerts
<!-- INSERT SCREENSHOT: grep "integrity-monitor" /var/log/syslog -->

### Screenshot: Cron Configuration
<!-- INSERT SCREENSHOT: cat /etc/cron.d/integrity-monitor -->

---

*Scripts developed with AI assistance and deployed by Linux Systems Administration Team*
