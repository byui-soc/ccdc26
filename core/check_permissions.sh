#!/usr/bin/env bash

function check_permissions {
    print_banner "Checking and Setting Permissions"

    # Fix critical file permissions
    sudo chown root:root /etc/shadow 2>/dev/null || true
    sudo chown root:root /etc/passwd 2>/dev/null || true
    sudo chmod 640 /etc/shadow 2>/dev/null || true
    sudo chmod 644 /etc/passwd 2>/dev/null || true

    log_info "Scanning for SUID binaries (this may take a moment)..."
    sudo find / -perm -4000 2>/dev/null | head -50 || true
    echo ""

    log_info "Checking for world-writable directories (max depth 3)..."
    sudo find / -maxdepth 3 -type d -perm -777 2>/dev/null | head -20 || true
    echo ""

    # Check if getcap is available
    if command -v getcap >/dev/null 2>&1; then
        log_info "Scanning for files with capabilities..."
        sudo getcap -r / 2>/dev/null | head -20 || true
        echo ""
    else
        log_info "getcap not available - skipping capability check"
    fi

    # Check if getfacl is available
    if command -v getfacl >/dev/null 2>&1; then
        log_info "Checking for extended ACLs in critical directories..."
        for dir in /etc /usr /root; do
            if [ -d "$dir" ]; then
                sudo getfacl -R "$dir" 2>/dev/null | grep -E "^# file:|user::|group::" | head -20 || true
            fi
        done
    else
        log_info "getfacl not available - skipping ACL check"
    fi

    log_success "Permission check completed"
}
