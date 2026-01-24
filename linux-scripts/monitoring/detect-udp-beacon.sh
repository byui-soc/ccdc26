#!/bin/bash
#=============================================================================
# UDP BEACON DETECTOR - Linux Version
#
# Purpose: Detect beaconing malware that uses UDP packets
# Method:  Monitor UDP connections and identify periodic/suspicious patterns
#
# Generated with AI assistance (Claude) for CCDC malware detection
#=============================================================================

set -uo pipefail

# Configuration
SYSLOG_TAG="udp-beacon-detector"
STATE_FILE="/var/run/udp-beacon-state"
SAMPLE_DURATION=60  # seconds to sample UDP traffic
BEACON_THRESHOLD=5  # connections to same dest = suspicious

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

QUIET=false
HOSTNAME=$(hostname)

log_alert() {
    [[ "$QUIET" == "false" ]] && echo -e "${RED}[ALERT]${NC} $1"
    logger -t "$SYSLOG_TAG" "ALERT: $1"
}

log_info() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    [[ "$QUIET" == "false" ]] && echo -e "${YELLOW}[WARN]${NC} $1"
}

# Get process info for a connection
get_process_info() {
    local local_port="$1"
    local pid=$(ss -ulnp sport = :$local_port 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1)
    
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        local user=$(stat -c '%U' "/proc/$pid" 2>/dev/null || echo "unknown")
        local exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        local cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
        echo "$pid|$user|$exe|${cmdline:0:100}"
    else
        echo "unknown|unknown|unknown|unknown"
    fi
}

# Detect UDP beaconing patterns
detect_udp_beacons() {
    log_info "=== UDP Beacon Detection Started on $HOSTNAME ==="
    log_info "Sampling UDP traffic for ${SAMPLE_DURATION} seconds..."
    
    local found_beacons=0
    declare -A udp_destinations
    declare -A connection_details
    
    # Method 1: Check current UDP connections
    log_info "Checking established UDP connections..."
    
    while IFS= read -r line; do
        [[ "$line" == "State"* ]] && continue
        [[ -z "$line" ]] && continue
        
        local local_addr=$(echo "$line" | awk '{print $4}')
        local peer_addr=$(echo "$line" | awk '{print $5}')
        local process=$(echo "$line" | awk '{print $6}')
        
        # Skip listening sockets (peer is *)
        [[ "$peer_addr" == "*:*" ]] && continue
        [[ "$peer_addr" == "0.0.0.0:*" ]] && continue
        
        local peer_ip="${peer_addr%:*}"
        local peer_port="${peer_addr##*:}"
        local local_port="${local_addr##*:}"
        
        # Skip localhost
        [[ "$peer_ip" == "127.0.0.1" ]] && continue
        [[ "$peer_ip" == "::1" ]] && continue
        
        # Track destination frequency
        local dest_key="${peer_ip}:${peer_port}"
        ((udp_destinations[$dest_key]++))
        
        # Get process details
        local proc_info=$(get_process_info "$local_port")
        connection_details[$dest_key]="$proc_info"
        
    done < <(ss -ulnp 2>/dev/null)
    
    # Method 2: Capture UDP packets for pattern analysis
    if command -v tcpdump &>/dev/null; then
        log_info "Capturing UDP packets for analysis..."
        
        local capture_file=$(mktemp)
        timeout "$SAMPLE_DURATION" tcpdump -i any -c 1000 udp -n 2>/dev/null | \
            grep -oP '\d+\.\d+\.\d+\.\d+\.\d+ > \d+\.\d+\.\d+\.\d+\.\d+' | \
            while read -r flow; do
                local src=$(echo "$flow" | cut -d'>' -f1 | xargs)
                local dst=$(echo "$flow" | cut -d'>' -f2 | xargs)
                echo "$dst"
            done | sort | uniq -c | sort -rn > "$capture_file"
        
        # Check for repeated destinations (beaconing pattern)
        while read -r count dest; do
            if [[ "$count" -ge "$BEACON_THRESHOLD" ]]; then
                local dest_ip="${dest%.*}"
                local dest_port="${dest##*.}"
                
                # Skip common legitimate UDP (DNS, NTP, DHCP)
                [[ "$dest_port" == "53" ]] && continue
                [[ "$dest_port" == "123" ]] && continue
                [[ "$dest_port" == "67" || "$dest_port" == "68" ]] && continue
                
                log_warn "Potential beacon pattern: $count packets to $dest_ip:$dest_port"
                ((udp_destinations["$dest_ip:$dest_port"]+=$count))
            fi
        done < "$capture_file"
        
        rm -f "$capture_file"
    fi
    
    # Method 3: Check for suspicious UDP processes
    log_info "Checking for suspicious UDP-using processes..."
    
    while IFS= read -r line; do
        local proc_name=$(echo "$line" | awk '{print $11}')
        local pid=$(echo "$line" | awk '{print $2}')
        
        # Flag suspicious process names
        case "$proc_name" in
            *python*|*perl*|*ruby*|*nc*|*ncat*|*socat*)
                local exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
                local cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
                log_warn "Suspicious UDP process: pid=$pid exe=$exe cmd=${cmdline:0:80}"
                ;;
        esac
    done < <(ps aux | grep -E 'udp|dgram' 2>/dev/null | grep -v grep)
    
    # Report findings
    echo ""
    log_info "=== UDP Connection Summary ==="
    
    for dest in "${!udp_destinations[@]}"; do
        local count=${udp_destinations[$dest]}
        local details=${connection_details[$dest]:-"unknown|unknown|unknown|unknown"}
        
        IFS='|' read -r pid user exe cmdline <<< "$details"
        
        if [[ "$count" -ge "$BEACON_THRESHOLD" ]]; then
            ((found_beacons++))
            log_alert "UDP BEACON DETECTED: dest=$dest count=$count pid=$pid user=$user exe=$exe"
        else
            log_info "UDP connection: dest=$dest count=$count"
        fi
    done
    
    echo ""
    if [[ $found_beacons -gt 0 ]]; then
        log_alert "Found $found_beacons potential UDP beacon(s)"
        return 1
    else
        log_info "No UDP beaconing detected"
        return 0
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet|-q) QUIET=true; shift ;;
        --duration|-d) SAMPLE_DURATION="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--quiet] [--duration SECONDS]"
            exit 0
            ;;
        *) shift ;;
    esac
done

# Run detection
detect_udp_beacons
