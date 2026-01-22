#!/bin/bash
#=============================================================================
# Investigate Suspicious Files on Ecom Server
#=============================================================================
# Found in /home/sysadmin on Ubuntu Ecom (172.20.242.30):
# - install-ssh-req.sh (installs paramiko - same as malware uses)
# - opencart-master/ directory and master.zip
#
# This script investigates these files and checks for malware connections
#
# Usage:
#   sudo ./investigate-ecom-suspicious-files.sh
#=============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "=================================================="
echo "  Investigating Suspicious Files on Ecom Server"
echo "=================================================="
echo ""

# Check if we're on the right machine
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
echo "Host: $HOSTNAME"
echo "IP: $IP"
echo ""

if [[ "$IP" != "172.20.242.30" ]]; then
    warn "This script is designed for the Ecom server (172.20.242.30)"
    warn "Current IP: $IP"
    read -p "Continue anyway? (y/n): " confirm
    [ "$confirm" != "y" ] && exit 0
fi

# 1. Investigate install-ssh-req.sh
info "[1/5] Investigating install-ssh-req.sh..."
if [ -f /home/sysadmin/install-ssh-req.sh ]; then
    echo "  ✓ File found: /home/sysadmin/install-ssh-req.sh"
    echo ""
    echo "  Content:"
    cat /home/sysadmin/install-ssh-req.sh | sed 's/^/    /'
    echo ""
    
    # Check when it was created/modified
    echo "  File details:"
    ls -la /home/sysadmin/install-ssh-req.sh | sed 's/^/    /'
    echo ""
    
    # Check if paramiko is installed
    if python3 -c "import paramiko" 2>/dev/null; then
        warn "  ⚠️  paramiko IS installed (used by startup_check malware)"
    else
        echo "  - paramiko not installed"
    fi
    
    # Check file hash
    echo "  File hash (for comparison):"
    md5sum /home/sysadmin/install-ssh-req.sh | sed 's/^/    /'
    sha256sum /home/sysadmin/install-ssh-req.sh | sed 's/^/    /'
else
    echo "  - File not found"
fi
echo ""

# 2. Investigate opencart-master directory
info "[2/5] Investigating opencart-master directory..."
if [ -d /home/sysadmin/opencart-master ]; then
    echo "  ✓ Directory found: /home/sysadmin/opencart-master"
    echo ""
    echo "  Directory details:"
    ls -lad /home/sysadmin/opencart-master | sed 's/^/    /'
    echo ""
    echo "  Contents (top level):"
    ls -la /home/sysadmin/opencart-master/ | head -20 | sed 's/^/    /'
    echo ""
    
    # Check for version info
    if [ -f /home/sysadmin/opencart-master/upload/VERSION ]; then
        echo "  OpenCart Version:"
        cat /home/sysadmin/opencart-master/upload/VERSION | sed 's/^/    /'
    fi
    
    # Check for suspicious PHP files
    echo "  Checking for suspicious PHP files..."
    SUSPICIOUS=$(find /home/sysadmin/opencart-master -name "*.php" -exec grep -l "eval\|base64_decode.*eval\|system\|exec\|shell_exec" {} \; 2>/dev/null | head -5)
    if [ -n "$SUSPICIOUS" ]; then
        warn "  Found files with potentially dangerous functions:"
        echo "$SUSPICIOUS" | sed 's/^/    /'
    else
        echo "  - No obvious backdoors found"
    fi
else
    echo "  - Directory not found"
fi
echo ""

# 3. Investigate master.zip
info "[3/5] Investigating master.zip..."
if [ -f /home/sysadmin/master.zip ]; then
    echo "  ✓ File found: /home/sysadmin/master.zip"
    echo ""
    echo "  File details:"
    ls -la /home/sysadmin/master.zip | sed 's/^/    /'
    echo ""
    
    # Check file hash
    echo "  File hash:"
    md5sum /home/sysadmin/master.zip | sed 's/^/    /'
    
    # List contents without extracting
    echo ""
    echo "  Archive contents (first 20 files):"
    unzip -l /home/sysadmin/master.zip 2>/dev/null | head -25 | tail -20 | sed 's/^/    /'
else
    echo "  - File not found"
fi
echo ""

# 4. Check for connections to malware infrastructure
info "[4/5] Checking for malware connections..."

# Check if any of these files reference IPs from malware config
if [ -f /etc/config.txt ]; then
    warn "  ⚠️  Malware config.txt still exists!"
    echo "  Content:"
    cat /etc/config.txt | sed 's/^/    /'
    echo ""
fi

# Check if install-ssh-req.sh was used by startup_check
if [ -f /var/log/startup_check.log ]; then
    warn "  ⚠️  Malware log still exists!"
    echo "  Recent entries:"
    tail -10 /var/log/startup_check.log | sed 's/^/    /'
    echo ""
fi

# Check if paramiko was recently installed
if [ -f /var/log/apt/history.log ]; then
    echo "  Recent paramiko installations:"
    grep -i "paramiko" /var/log/apt/history.log | tail -5 | sed 's/^/    /'
fi
echo ""

# 5. Recommendations
info "[5/5] Recommendations..."
echo ""

if [ -f /home/sysadmin/install-ssh-req.sh ]; then
    warn "RECOMMENDED ACTIONS:"
    echo "  1. Remove install-ssh-req.sh (likely related to malware):"
    echo "     sudo rm /home/sysadmin/install-ssh-req.sh"
    echo ""
fi

if [ -d /home/sysadmin/opencart-master ] || [ -f /home/sysadmin/master.zip ]; then
    warn "OPENCART SOURCE FILES:"
    echo "  2. Move OpenCart source files to secure location or remove:"
    echo "     sudo mv /home/sysadmin/opencart-master /root/backup/"
    echo "     sudo mv /home/sysadmin/master.zip /root/backup/"
    echo "  (Keeping them in /home/sysadmin exposes version info to attackers)"
    echo ""
fi

if python3 -c "import paramiko" 2>/dev/null; then
    warn "PARAMIKO INSTALLED:"
    echo "  3. Consider if paramiko is needed for legitimate use"
    echo "     If not, remove it:"
    echo "     sudo apt remove -y python3-paramiko"
    echo ""
fi

echo "=================================================="
echo "  Investigation Complete"
echo "=================================================="
echo ""
info "Review the findings above and take appropriate action."
echo ""
