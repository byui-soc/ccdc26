#!/usr/bin/env bash

function sysctl_config {
    print_banner "Applying sysctl Configurations"

    local file="/etc/sysctl.conf"
    local applied=0
    local skipped=0

    # Helper function to safely add sysctl setting
    add_sysctl_setting() {
        local setting="$1"
        local value="$2"
        local proc_path="/proc/sys/${setting//./\/}"
        
        # Check if the sysctl parameter exists
        if [ -f "$proc_path" ] || sudo sysctl -n "$setting" >/dev/null 2>&1; then
            # Check if already in config to avoid duplicates
            if ! grep -q "^${setting}" "$file" 2>/dev/null; then
                echo "${setting} = ${value}" | sudo tee -a "$file" >/dev/null
                applied=$((applied + 1))
            fi
            # Try to apply it now
            sudo sysctl -w "${setting}=${value}" >/dev/null 2>&1 || {
                log_warning "Could not apply ${setting} (may require reboot)"
            }
        else
            log_verbose "Skipping ${setting} (not available on this kernel)"
            skipped=$((skipped + 1))
        fi
    }

    log_info "Applying sysctl security hardening settings..."

    # Network hardening
    add_sysctl_setting "net.ipv4.tcp_syncookies" "1"
    add_sysctl_setting "net.ipv4.tcp_synack_retries" "2"
    add_sysctl_setting "net.ipv4.tcp_challenge_ack_limit" "1000000"
    add_sysctl_setting "net.ipv4.tcp_rfc1337" "1"
    add_sysctl_setting "net.ipv4.icmp_ignore_bogus_error_responses" "1"
    add_sysctl_setting "net.ipv4.conf.all.accept_redirects" "0"
    add_sysctl_setting "net.ipv4.icmp_echo_ignore_all" "1"

    # Kernel hardening
    add_sysctl_setting "kernel.core_uses_pid" "1"
    add_sysctl_setting "kernel.kptr_restrict" "2"
    add_sysctl_setting "kernel.perf_event_paranoid" "2"
    add_sysctl_setting "kernel.randomize_va_space" "2"
    add_sysctl_setting "kernel.sysrq" "0"
    add_sysctl_setting "kernel.yama.ptrace_scope" "2"
    add_sysctl_setting "kernel.unprivileged_userns_clone" "0"

    # Filesystem hardening
    add_sysctl_setting "fs.protected_hardlinks" "1"
    add_sysctl_setting "fs.protected_symlinks" "1"
    add_sysctl_setting "fs.suid_dumpable" "0"
    add_sysctl_setting "fs.protected_fifos" "2"
    add_sysctl_setting "fs.protected_regular" "2"

    log_info "Applied ${applied} sysctl settings, skipped ${skipped} unsupported settings"
    log_success "Sysctl hardening completed"
}
