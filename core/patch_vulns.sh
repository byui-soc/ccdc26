#!/usr/bin/env bash

function patch_vulnerabilities {
    print_banner "Patching Vulnerabilities"

    # Fix pkexec permissions (CVE-2021-4034 - PwnKit)
    if [ -f /usr/bin/pkexec ]; then
        log_info "Setting secure permissions on pkexec..."
        sudo chmod 0755 /usr/bin/pkexec 2>/dev/null || {
            log_warning "Could not set permissions on pkexec"
        }
    else
        log_info "pkexec not found - skipping"
    fi

    # Disable unprivileged user namespaces (if supported by kernel)
    # This mitigates various container escape and privilege escalation vulnerabilities
    if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
        log_info "Disabling unprivileged user namespaces..."
        sudo sysctl -w kernel.unprivileged_userns_clone=0 2>/dev/null || {
            log_warning "Could not set kernel.unprivileged_userns_clone"
        }
        
        # Make it persistent
        if ! grep -q "kernel.unprivileged_userns_clone" /etc/sysctl.conf 2>/dev/null; then
            echo "kernel.unprivileged_userns_clone = 0" | sudo tee -a /etc/sysctl.conf >/dev/null
        fi
    else
        log_info "kernel.unprivileged_userns_clone not available on this kernel - skipping"
    fi

    # Apply sysctl changes
    sudo sysctl -p >/dev/null 2>&1 || {
        log_warning "Some sysctl settings could not be applied"
    }
    
    log_success "Vulnerability patching completed"
}
