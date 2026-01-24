#!/bin/bash
#=============================================================================
# OUTBOUND SSH CONNECTION DETECTOR
# 
# Purpose: Detect and alert on outbound SSH connections (malware indicator)
# 
# Features:
#   - Lists established TCP connections with owning process
#   - Flags outbound SSH (remote port 22 or ssh process with TCP connection)
#   - Whitelist support for known-good destinations
#   - De-duplicated syslog alerts (one per unique connection)
#   - Detailed logging: timestamp, host, dest, pid, user, exe, cmdline
#
# Usage:
#   ./detect-outbound-ssh.sh              # Run once
#   ./detect-outbound-ssh.sh --daemon     # Run continuously (every 30s)
#   ./detect-outbound-ssh.sh --quiet      # No console output, syslog only
#
# Install as cron:
#   * * * * * /opt/ccdc-toolkit/linux-scripts/monitoring/detect-outbound-ssh.sh --quiet
#
# Generated for CCDC malware detection
#=============================================================================

set -uo pipefail

#=============================================================================
# CONFIGURATION
#=============================================================================

# Default SSH ports to monitor
SSH_DEFAULT_PORTS="22"

# State file for de-duplication (tracks already-alerted connections)
STATE_FILE="/var/run/ssh-detector-state"

# Syslog configuration
SYSLOG_FACILITY="local0"
SYSLOG_PRIORITY="warning"
SYSLOG_TAG="ssh-detector"

# Whitelist file (one entry per line: IP, CIDR, or IP:port)
WHITELIST_FILE="/etc/ssh-detector-whitelist.conf"

# Built-in whitelist (add known-good SSH destinations)
BUILTIN_WHITELIST=(
    "127.0.0.1"
    "::1"
    # Add competition infrastructure IPs here if needed
    # "172.25.20.0/24"
)

#=============================================================================
# COLORS
#=============================================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

#=============================================================================
# GLOBALS
#=============================================================================
QUIET=false
DAEMON=false
HOSTNAME=$(hostname)

#=============================================================================
# FUNCTIONS
#=============================================================================

log_alert() {
    local message="$1"
    
    # Console output (unless quiet)
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${RED}[ALERT]${NC} $message"
    fi
    
    # Syslog
    logger -p "${SYSLOG_FACILITY}.${SYSLOG_PRIORITY}" -t "$SYSLOG_TAG" "$message"
}

log_info() {
    if [[ "$QUIET" == "false" ]]; then
        echo -e "${GREEN}[INFO]${NC} $1"
    fi
}

# Check if IP matches whitelist
is_whitelisted() {
    local ip="$1"
    local port="${2:-}"
    
    # Check built-in whitelist
    for entry in "${BUILTIN_WHITELIST[@]}"; do
        if [[ "$ip" == "$entry" ]]; then
            return 0
        fi
        # CIDR check (basic - just prefix match for /24, /16, /8)
        if [[ "$entry" == *"/"* ]]; then
            local network="${entry%/*}"
            local prefix="${network%.*}"
            if [[ "$ip" == "$prefix"* ]]; then
                return 0
            fi
        fi
    done
    
    # Check whitelist file
    if [[ -f "$WHITELIST_FILE" ]]; then
        while IFS= read -r entry; do
            # Skip comments and empty lines
            [[ "$entry" =~ ^# ]] && continue
            [[ -z "$entry" ]] && continue
            
            # Check IP or IP:port
            if [[ "$entry" == *":"* ]]; then
                # IP:port format
                if [[ "$ip:$port" == "$entry" ]]; then
                    return 0
                fi
            else
                # IP or CIDR format
                if [[ "$ip" == "$entry" ]]; then
                    return 0
                fi
                # Basic CIDR check
                if [[ "$entry" == *"/"* ]]; then
                    local network="${entry%/*}"
                    local prefix="${network%.*}"
                    if [[ "$ip" == "$prefix"* ]]; then
                        return 0
                    fi
                fi
            fi
        done < "$WHITELIST_FILE"
    fi
    
    return 1
}

# Check if connection was already alerted (de-duplication)
is_already_alerted() {
    local conn_key="$1"
    
    if [[ -f "$STATE_FILE" ]]; then
        grep -q "^${conn_key}$" "$STATE_FILE" 2>/dev/null && return 0
    fi
    
    return 1
}

# Mark connection as alerted
mark_alerted() {
    local conn_key="$1"
    echo "$conn_key" >> "$STATE_FILE"
}

# Clean state file (remove stale entries)
clean_state_file() {
    # Keep state file from growing too large
    if [[ -f "$STATE_FILE" ]]; then
        tail -1000 "$STATE_FILE" > "${STATE_FILE}.tmp" 2>/dev/null
        mv "${STATE_FILE}.tmp" "$STATE_FILE" 2>/dev/null
    fi
}

# Get process details
get_process_details() {
    local pid="$1"
    local user exe cmdline
    
    if [[ -d "/proc/$pid" ]]; then
        user=$(stat -c '%U' "/proc/$pid" 2>/dev/null || echo "unknown")
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
        # Trim cmdline
        cmdline="${cmdline:0:200}"
    else
        user="unknown"
        exe="unknown"
        cmdline="unknown"
    fi
    
    echo "$user|$exe|$cmdline"
}

# Main detection function
detect_outbound_ssh() {
    local found_suspicious=0
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    log_info "Scanning for outbound SSH connections..."
    
    # Get established TCP connections with process info
    # Format: State Recv-Q Send-Q Local:Port Peer:Port Process
    while IFS= read -r line; do
        # Parse ss output
        local state local_addr peer_addr process_info
        
        # Skip header
        [[ "$line" == "State"* ]] && continue
        [[ "$line" == "ESTAB"* ]] || continue
        
        # Extract fields
        state=$(echo "$line" | awk '{print $1}')
        local_addr=$(echo "$line" | awk '{print $4}')
        peer_addr=$(echo "$line" | awk '{print $5}')
        process_info=$(echo "$line" | awk '{print $6}')
        
        # Extract peer IP and port
        local peer_ip peer_port
        if [[ "$peer_addr" == "["*"]:"* ]]; then
            # IPv6
            peer_ip=$(echo "$peer_addr" | sed 's/\[\(.*\)\]:.*/\1/')
            peer_port=$(echo "$peer_addr" | sed 's/.*]://')
        else
            # IPv4
            peer_ip="${peer_addr%:*}"
            peer_port="${peer_addr##*:}"
        fi
        
        # Extract PID from process info
        local pid=""
        if [[ "$process_info" =~ pid=([0-9]+) ]]; then
            pid="${BASH_REMATCH[1]}"
        fi
        
        # Extract process name
        local proc_name=""
        if [[ "$process_info" =~ \"([^\"]+)\" ]]; then
            proc_name="${BASH_REMATCH[1]}"
        fi
        
        # Check if this is outbound SSH
        local is_ssh=false
        
        # Condition 1: Remote port is SSH default (22)
        if [[ " $SSH_DEFAULT_PORTS " == *" $peer_port "* ]]; then
            is_ssh=true
        fi
        
        # Condition 2: Process name is ssh-related with established TCP
        if [[ "$proc_name" == "ssh" || "$proc_name" == "sshd" || \
              "$proc_name" == "python"* || "$proc_name" == "paramiko"* ]]; then
            # Check if it's an outbound connection (not listening)
            if [[ "$peer_port" != "22" && "$state" == "ESTAB" ]]; then
                # Could be SSH on non-standard port
                is_ssh=true
            fi
        fi
        
        # Skip if not SSH
        [[ "$is_ssh" == "false" ]] && continue
        
        # Skip if whitelisted
        if is_whitelisted "$peer_ip" "$peer_port"; then
            continue
        fi
        
        # Create unique connection key for de-duplication
        local conn_key="${peer_ip}:${peer_port}:${pid}"
        
        # Skip if already alerted
        if is_already_alerted "$conn_key"; then
            continue
        fi
        
        # Get process details
        local proc_details user exe cmdline
        if [[ -n "$pid" ]]; then
            proc_details=$(get_process_details "$pid")
            IFS='|' read -r user exe cmdline <<< "$proc_details"
        else
            user="unknown"
            exe="unknown"
            cmdline="unknown"
        fi
        
        # Generate alert
        local alert_msg="OUTBOUND SSH DETECTED: "
        alert_msg+="host=$HOSTNAME "
        alert_msg+="dest=${peer_ip}:${peer_port} "
        alert_msg+="pid=${pid:-unknown} "
        alert_msg+="user=$user "
        alert_msg+="exe=$exe "
        alert_msg+="cmdline=\"$cmdline\""
        
        log_alert "$alert_msg"
        
        # Mark as alerted
        mark_alerted "$conn_key"
        
        ((found_suspicious++))
        
    done < <(ss -pt state established 2>/dev/null)
    
    # Summary
    if [[ $found_suspicious -eq 0 ]]; then
        log_info "No suspicious outbound SSH connections detected"
    else
        log_alert "Found $found_suspicious suspicious outbound SSH connection(s)"
    fi
    
    return $found_suspicious
}

# Daemon mode - continuous monitoring
run_daemon() {
    log_info "Starting SSH detector daemon (interval: 30s)"
    log_info "Press Ctrl+C to stop"
    
    while true; do
        detect_outbound_ssh
        clean_state_file
        sleep 30
    done
}

# Show usage
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --daemon    Run continuously (every 30 seconds)"
    echo "  --quiet     Suppress console output (syslog only)"
    echo "  --help      Show this help message"
    echo ""
    echo "Whitelist file: $WHITELIST_FILE"
    echo "Format: One entry per line (IP, CIDR, or IP:port)"
    echo ""
    echo "Example whitelist:"
    echo "  # Known good SSH destinations"
    echo "  192.168.1.100"
    echo "  10.0.0.0/8"
    echo "  172.16.1.50:22"
    exit 0
}

#=============================================================================
# MAIN
#=============================================================================

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon|-d)
            DAEMON=true
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Ensure state directory exists
touch "$STATE_FILE" 2>/dev/null || STATE_FILE="/tmp/ssh-detector-state"

# Run
if [[ "$DAEMON" == "true" ]]; then
    run_daemon
else
    detect_outbound_ssh
    exit $?
fi
