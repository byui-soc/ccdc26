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
