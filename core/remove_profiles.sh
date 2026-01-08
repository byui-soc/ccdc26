#!/usr/bin/env bash

# Profile files are shell initialization scripts that run when users log in.
# They can be used by attackers for persistence or malicious code execution.
# This function backs up system-wide profiles and removes user profiles
# (except for CCDC users and root).

function remove_profiles {
    print_banner "Removing Profile Files"

    # Backup system-wide profile directory if it exists
    if [ -d /etc/profile.d ]; then
        sudo mv /etc/profile.d /etc/profile.d.bak 2>/dev/null || {
            log_warning "Could not backup /etc/profile.d - may already be backed up or permission denied"
        }
    else
        log_info "/etc/profile.d does not exist - skipping"
    fi

    # Backup system-wide profile file if it exists
    if [ -f /etc/profile ]; then
        sudo mv /etc/profile /etc/profile.bak 2>/dev/null || {
            log_warning "Could not backup /etc/profile - may already be backed up or permission denied"
        }
    else
        log_info "/etc/profile does not exist - skipping"
    fi

    # Remove user profile files (excluding CCDC users and root)
    log_info "Removing user profile files (excluding root and CCDC users)..."
    for f in ".profile" ".bashrc" ".bash_login"; do
        # Use find with proper error handling
        if ! sudo find /home /root \( \
            -path "/root/*" -o -path "/home/ccdcuser1/*" -o -path "/home/ccdcuser2/*" \
        \) -prune -o -name "$f" -type f -exec sudo rm -f {} \; 2>/dev/null; then
            log_warning "Some profile files could not be removed (may not exist or permission denied)"
        fi
    done

    log_success "Profile file removal completed"
}
