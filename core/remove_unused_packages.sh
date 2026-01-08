#!/usr/bin/env bash

function remove_unused_packages {
    print_banner "Removing Unused Packages"

    # List of potentially dangerous/unused development and networking tools
    local packages_to_remove="netcat nc gcc cmake make telnet"
    
    if command -v yum >/dev/null 2>&1; then
        log_info "Using yum to remove packages..."
        # yum uses 'remove' not 'purge'
        sudo yum remove -y -q $packages_to_remove 2>/dev/null || {
            log_warning "Some packages could not be removed (may not be installed)"
        }
    elif command -v dnf >/dev/null 2>&1; then
        log_info "Using dnf to remove packages..."
        # dnf also uses 'remove' not 'purge'
        sudo dnf remove -y -q $packages_to_remove 2>/dev/null || {
            log_warning "Some packages could not be removed (may not be installed)"
        }
    elif command -v apt-get >/dev/null 2>&1; then
        log_info "Using apt-get to purge packages..."
        sudo apt-get -y purge $packages_to_remove 2>/dev/null || {
            log_warning "Some packages could not be removed (may not be installed)"
        }
    elif command -v apk >/dev/null 2>&1; then
        log_info "Using apk to remove packages..."
        sudo apk del gcc make 2>/dev/null || {
            log_warning "Some packages could not be removed (may not be installed)"
        }
    else
        log_warning "Unsupported package manager for package removal"
        log_info "Manually remove: netcat, nc, gcc, cmake, make, telnet"
    fi
    
    log_success "Unused package removal completed"
}
