#!/bin/bash
# Brady Hodge - CCDC26 Linux Toolkit - User Account Hardening
# Handles: password changes, unauthorized users, sudo access

source "$(dirname "$0")/../utils/common.sh"
require_root

header "User Account Hardening"

#=============================================================================
# CONFIGURATION - EDIT THESE FOR YOUR COMPETITION
#=============================================================================
# Add your authorized users here (space-separated)
AUTHORIZED_USERS="root"  # Add your team's users: "root admin operator"

# Users that should have sudo access (space-separated)
AUTHORIZED_SUDO="root"   # Add sudo users: "root admin"

# Password to set for all users (or leave empty to generate random)
# In competition, you probably want to set this to something your team knows
TEAM_PASSWORD=""

#=============================================================================
# PASSWORD MANAGEMENT
#=============================================================================
change_all_passwords() {
    header "Changing All User Passwords"
    
    local password_file="/root/ccdc-passwords-$(timestamp).txt"
    echo "# CCDC Password List - Generated $(date)" > "$password_file"
    chmod 600 "$password_file"
    
    for user in $(get_human_users); do
        local new_pass
        if [ -n "$TEAM_PASSWORD" ]; then
            new_pass="$TEAM_PASSWORD"
        else
            new_pass=$(generate_password 16)
        fi
        
        echo "$user:$new_pass" | chpasswd
        if [ $? -eq 0 ]; then
            success "Changed password for: $user"
            echo "$user : $new_pass" >> "$password_file"
        else
            error "Failed to change password for: $user"
        fi
    done
    
    warn "Passwords saved to: $password_file"
    warn "SECURE THIS FILE AND DELETE AFTER COMPETITION"
    log_action "Changed passwords for all users"
}

#=============================================================================
# UNAUTHORIZED USER DETECTION
#=============================================================================
audit_users() {
    header "Auditing User Accounts"
    
    # Check for users with UID 0 (besides root)
    info "Checking for non-root users with UID 0..."
    while IFS=: read -r username _ uid _; do
        if [ "$uid" -eq 0 ] && [ "$username" != "root" ]; then
            log_finding "UID 0 user found (not root): $username"
        fi
    done < /etc/passwd
    
    # Check for users with empty passwords
    info "Checking for users with empty passwords..."
    while IFS=: read -r username password _; do
        if [ -z "$password" ] || [ "$password" == "!" ] || [ "$password" == "*" ]; then
            continue  # Locked or no login
        fi
        if [ "${#password}" -lt 10 ]; then
            log_finding "Possibly weak/empty password hash for: $username"
        fi
    done < /etc/shadow
    
    # Check for unauthorized human users
    info "Checking for unauthorized users..."
    for user in $(get_human_users); do
        if ! echo "$AUTHORIZED_USERS" | grep -qw "$user"; then
            log_finding "Potentially unauthorized user: $user"
        fi
    done
    
    # Check for users with login shells that shouldn't have them
    info "Checking service accounts with shells..."
    while IFS=: read -r username _ uid _ _ _ shell; do
        if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
            if [ "$shell" != "/usr/sbin/nologin" ] && \
               [ "$shell" != "/bin/false" ] && \
               [ "$shell" != "/sbin/nologin" ] && \
               [ -n "$shell" ]; then
                log_finding "Service account with shell: $username ($shell)"
            fi
        fi
    done < /etc/passwd
}

#=============================================================================
# DISABLE UNAUTHORIZED USERS
#=============================================================================
disable_unauthorized_users() {
    header "Disabling Unauthorized Users"
    
    for user in $(get_human_users); do
        if ! echo "$AUTHORIZED_USERS" | grep -qw "$user"; then
            read -p "Disable user '$user'? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Lock account
                passwd -l "$user" 2>/dev/null
                usermod -s /usr/sbin/nologin "$user" 2>/dev/null
                
                # Kill their processes
                pkill -u "$user" 2>/dev/null
                
                # Expire account
                chage -E 0 "$user" 2>/dev/null
                
                success "Disabled user: $user"
                log_action "Disabled user: $user"
            fi
        fi
    done
}

#=============================================================================
# SUDO ACCESS AUDIT AND HARDENING
#=============================================================================
harden_sudo() {
    header "Hardening Sudo Access"
    
    # Backup sudoers
    backup_file /etc/sudoers
    
    # Audit current sudo users
    info "Current sudo/wheel group members:"
    getent group sudo 2>/dev/null || true
    getent group wheel 2>/dev/null || true
    
    # Check sudoers.d for suspicious entries
    info "Checking /etc/sudoers.d/ for suspicious entries..."
    if [ -d /etc/sudoers.d ]; then
        for f in /etc/sudoers.d/*; do
            if [ -f "$f" ]; then
                info "Found: $f"
                cat "$f"
                echo
            fi
        done
    fi
    
    # Remove unauthorized sudo users
    for user in $(get_sudo_users | sort -u); do
        if ! echo "$AUTHORIZED_SUDO" | grep -qw "$user"; then
            log_finding "Unauthorized sudo user: $user"
            read -p "Remove sudo access for '$user'? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Remove from sudo/wheel groups
                gpasswd -d "$user" sudo 2>/dev/null
                gpasswd -d "$user" wheel 2>/dev/null
                success "Removed sudo access for: $user"
                log_action "Removed sudo access for: $user"
            fi
        fi
    done
    
    # Harden sudoers settings
    info "Adding secure sudoers defaults..."
    
    # Create secure sudoers.d entry
    cat > /etc/sudoers.d/ccdc-hardening << 'EOF'
# CCDC Hardening - Secure sudo defaults
Defaults    env_reset
Defaults    mail_badpass
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input,log_output
Defaults    passwd_tries=3
Defaults    passwd_timeout=1
Defaults    timestamp_timeout=5
EOF
    chmod 440 /etc/sudoers.d/ccdc-hardening
    
    # Validate sudoers
    if visudo -c; then
        success "Sudoers configuration valid"
    else
        error "Sudoers configuration invalid! Restoring backup..."
        cp /etc/sudoers.bak.* /etc/sudoers 2>/dev/null
    fi
}

#=============================================================================
# PASSWORD POLICY
#=============================================================================
set_password_policy() {
    header "Setting Password Policy"
    
    # Set password aging
    info "Setting password aging policies..."
    
    # For all existing users
    for user in $(get_human_users); do
        chage -M 90 -m 1 -W 7 "$user" 2>/dev/null
    done
    
    # Update login.defs
    backup_file /etc/login.defs
    
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs 2>/dev/null
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs 2>/dev/null
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs 2>/dev/null
    
    # Set umask
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs 2>/dev/null
    
    success "Password policy configured"
    log_action "Set password policy"
}

#=============================================================================
# LOCK ROOT DIRECT LOGIN (Optional - use with caution)
#=============================================================================
secure_root() {
    header "Securing Root Account"
    
    # Disable root login via password (still allow sudo)
    warn "This will disable direct root password login"
    warn "Make sure you have another sudo user!"
    
    read -p "Disable root password login? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        passwd -l root
        success "Root password login disabled"
        warn "Use 'sudo -i' or 'su -' from authorized sudo users"
        log_action "Disabled root password login"
    fi
}

#=============================================================================
# MAIN MENU
#=============================================================================
main() {
    echo ""
    echo "User Hardening Options:"
    echo "1) Audit users only (no changes)"
    echo "2) Change all passwords"
    echo "3) Disable unauthorized users"
    echo "4) Harden sudo access"
    echo "5) Set password policy"
    echo "6) Secure root account"
    echo "7) Run ALL (recommended for competition start)"
    echo ""
    read -p "Select option [1-7]: " choice
    
    case $choice in
        1) audit_users ;;
        2) change_all_passwords ;;
        3) audit_users; disable_unauthorized_users ;;
        4) harden_sudo ;;
        5) set_password_policy ;;
        6) secure_root ;;
        7)
            audit_users
            change_all_passwords
            disable_unauthorized_users
            harden_sudo
            set_password_policy
            ;;
        *) error "Invalid option" ;;
    esac
}

# Run if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
