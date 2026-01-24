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

# Statistics
TOTAL_MODIFIED=0
TOTAL_NEW=0
TOTAL_DELETED=0
TOTAL_CHECKED=0

#=============================================================================
# FUNCTIONS
#=============================================================================

usage() {
    echo "Usage: $0 [options] [directory1] [directory2] ..."
    echo ""
    echo "Options:"
    echo "  --all       Monitor all default critical directories"
    echo "  --quiet     Suppress console output (syslog only)"
    echo "  --help      Show this help message"
    echo ""
    echo "Default directories (--all):"
    for dir in "${DEFAULT_DIRECTORIES[@]}"; do
        echo "  - $dir"
    done
    echo ""
    echo "Examples:"
    echo "  $0 /etc /var/www"
    echo "  $0 --all"
    echo "  $0 --all --quiet"
    exit 0
}

log_info() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    [[ "$QUIET" == "false" ]] && echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    [[ "$QUIET" == "false" ]] && echo -e "${RED}[ERROR]${NC} $1"
}

log_alert() {
    [[ "$QUIET" == "false" ]] && echo -e "${RED}[ALERT]${NC} $1"
}

# Send alert to syslog
syslog_alert() {
    local message="$1"
    logger -p "${SYSLOG_FACILITY}.${SYSLOG_PRIORITY}" -t "$SYSLOG_TAG" "$message"
}

# Check a single directory against its baseline
check_directory() {
    local target_dir="$1"
    local db_file="${target_dir}/${DB_FILENAME}"
    local modified=0
    local new_files=0
    local deleted=0
    local checked=0
    
    # Check if baseline exists
    if [[ ! -f "$db_file" ]]; then
        log_warn "No baseline found for: $target_dir (run integrity-baseline.sh first)"
        return 1
    fi
    
    log_info "Checking: $target_dir"
    
    # Create associative array of baseline entries
    declare -A baseline_files
    
    while IFS='|' read -r hash perms owner size mtime filepath; do
        # Skip comments and empty lines
        [[ "$hash" =~ ^# ]] && continue
        [[ -z "$hash" ]] && continue
        
        baseline_files["$filepath"]="${hash}|${perms}|${owner}|${size}|${mtime}"
    done < "$db_file"
    
    # Track which baseline files we've seen
    declare -A seen_files
    
    # Check current files
    while IFS= read -r -d '' file; do
        # Skip the database file
        [[ "$file" == "$db_file" ]] && continue
        [[ ! -f "$file" ]] && continue
        
        ((checked++))
        seen_files["$file"]=1
        
        # Get current file attributes
        local current_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        local current_perms=$(stat -c '%a' "$file" 2>/dev/null)
        local current_owner=$(stat -c '%U:%G' "$file" 2>/dev/null)
        local current_size=$(stat -c '%s' "$file" 2>/dev/null)
        local current_mtime=$(stat -c '%Y' "$file" 2>/dev/null)
        
        if [[ -v "baseline_files[$file]" ]]; then
            # File exists in baseline - check for modifications
            IFS='|' read -r base_hash base_perms base_owner base_size base_mtime <<< "${baseline_files[$file]}"
            
            if [[ "$current_hash" != "$base_hash" ]]; then
                ((modified++))
                local alert_msg="MODIFIED FILE: $file (hash changed)"
                log_alert "$alert_msg"
                syslog_alert "$alert_msg"
            elif [[ "$current_perms" != "$base_perms" ]]; then
                ((modified++))
                local alert_msg="PERMISSION CHANGE: $file ($base_perms -> $current_perms)"
                log_alert "$alert_msg"
                syslog_alert "$alert_msg"
            elif [[ "$current_owner" != "$base_owner" ]]; then
                ((modified++))
                local alert_msg="OWNER CHANGE: $file ($base_owner -> $current_owner)"
                log_alert "$alert_msg"
                syslog_alert "$alert_msg"
            fi
        else
            # New file not in baseline
            ((new_files++))
            local alert_msg="NEW FILE: $file (not in baseline)"
            log_alert "$alert_msg"
            syslog_alert "$alert_msg"
        fi
    done < <(find "$target_dir" -type f -print0 2>/dev/null)
    
    # Check for deleted files
    for filepath in "${!baseline_files[@]}"; do
        if [[ ! -v "seen_files[$filepath]" ]]; then
            # Check if file actually doesn't exist (not just in a different subdir)
            if [[ ! -f "$filepath" ]]; then
                ((deleted++))
                local alert_msg="DELETED FILE: $filepath (missing from system)"
                log_alert "$alert_msg"
                syslog_alert "$alert_msg"
            fi
        fi
    done
    
    # Update totals
    ((TOTAL_MODIFIED += modified))
    ((TOTAL_NEW += new_files))
    ((TOTAL_DELETED += deleted))
    ((TOTAL_CHECKED += checked))
    
    # Summary for this directory
    if [[ $modified -gt 0 || $new_files -gt 0 || $deleted -gt 0 ]]; then
        log_warn "Directory $target_dir: $modified modified, $new_files new, $deleted deleted"
    else
        log_info "Directory $target_dir: OK ($checked files checked)"
    fi
}

#=============================================================================
# MAIN
#=============================================================================

QUIET="false"
USE_ALL="false"
DIRECTORIES=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            USE_ALL="true"
            shift
            ;;
        --quiet|-q)
            QUIET="true"
            shift
            ;;
        --help|-h)
            usage
            ;;
        -*)
            log_error "Unknown option: $1"
            usage
            ;;
        *)
            DIRECTORIES+=("$1")
            shift
            ;;
    esac
done

# Determine directories to check
if [[ "$USE_ALL" == "true" ]]; then
    for dir in "${DEFAULT_DIRECTORIES[@]}"; do
        [[ -d "$dir" ]] && DIRECTORIES+=("$dir")
    done
fi

# Validate we have directories to check
if [[ ${#DIRECTORIES[@]} -eq 0 ]]; then
    log_error "No directories specified"
    usage
fi

# Header
[[ "$QUIET" == "false" ]] && echo -e "${CYAN}=== Integrity Monitor Check: $(date) ===${NC}"

# Check each directory
for dir in "${DIRECTORIES[@]}"; do
    if [[ -d "$dir" ]]; then
        check_directory "$dir"
    else
        log_warn "Directory not found: $dir"
    fi
done

# Final summary
echo ""
[[ "$QUIET" == "false" ]] && echo -e "${CYAN}=== Summary ===${NC}"
log_info "Total files checked: $TOTAL_CHECKED"

if [[ $TOTAL_MODIFIED -gt 0 || $TOTAL_NEW -gt 0 || $TOTAL_DELETED -gt 0 ]]; then
    log_alert "CHANGES DETECTED: $TOTAL_MODIFIED modified, $TOTAL_NEW new, $TOTAL_DELETED deleted"
    syslog_alert "INTEGRITY CHECK SUMMARY: $TOTAL_MODIFIED modified, $TOTAL_NEW new, $TOTAL_DELETED deleted files"
    exit 1
else
    log_info "All files intact - no changes detected"
    exit 0
fi
