#!/bin/bash
# Brady Hodge - CCDC26 Linux Toolkit - Full System Hardening
# Run all hardening scripts in recommended order

source "$(dirname "$0")/../utils/common.sh"
require_root

SCRIPT_DIR="$(dirname "$0")"

header "CCDC26 Full System Hardening"

echo "This script will run all hardening procedures."
echo "It is recommended to run this at the START of competition."
echo ""
warn "Make sure you have console access in case SSH breaks!"
echo ""
read -p "Continue with full hardening? (y/n): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

# Prompt for team password FIRST before any changes
header "Password Configuration"
info "You will need a password for all user accounts."
warn "REMEMBER THIS PASSWORD - you will need it to log back in!"
echo ""
read -sp "Enter team password for ALL users: " TEAM_PASSWORD
echo ""
read -sp "Confirm password: " confirm_pass
echo ""

if [ "$TEAM_PASSWORD" != "$confirm_pass" ]; then
    error "Passwords do not match! Aborting."
    exit 1
fi

if [ -z "$TEAM_PASSWORD" ]; then
    error "Password cannot be empty! Aborting."
    exit 1
fi

export TEAM_PASSWORD
success "Password confirmed. Proceeding with hardening..."
echo ""

# Record start time
START_TIME=$(date +%s)

header "Phase 1: User Account Hardening"
info "Changing passwords and securing user accounts..."
# Run user hardening without password change (we'll do it ourselves)
source "$SCRIPT_DIR/users.sh"
audit_users
# Change passwords using the password we collected
password_file="/root/ccdc-passwords-$(timestamp).txt"
echo "# CCDC Password List - Generated $(date)" > "$password_file"
chmod 600 "$password_file"
for user in $(get_human_users); do
    echo "$user:$TEAM_PASSWORD" | chpasswd
    if [ $? -eq 0 ]; then
        success "Changed password for: $user"
        echo "$user : $TEAM_PASSWORD" >> "$password_file"
    else
        error "Failed to change password for: $user"
    fi
done
warn "Passwords saved to: $password_file"
disable_unauthorized_users
harden_sudo
set_password_policy

header "Phase 2: SSH Hardening"
info "Securing SSH configuration..."
bash "$SCRIPT_DIR/ssh.sh" <<< "7"

header "Phase 3: Firewall Configuration"
info "Setting up firewall rules..."
info "Detecting running services to avoid blocking scored services..."
# Source firewall.sh to get detected ports, then run with auto-configure
source "$SCRIPT_DIR/firewall.sh" 2>/dev/null || true
echo ""
warn "Firewall will allow these TCP ports: ${ALLOWED_TCP_PORTS:-22 80 443}"
warn "Firewall will allow these UDP ports: ${ALLOWED_UDP_PORTS:-none}"
echo ""
read -p "Proceed with these ports? (y to continue, n to skip firewall): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    bash "$SCRIPT_DIR/firewall.sh" <<< "2"
else
    warn "Skipping firewall configuration - configure manually!"
fi

header "Phase 4: Service Management"
info "Disabling dangerous services..."
bash "$SCRIPT_DIR/services.sh" <<< "7"

header "Phase 5: File Permissions"
info "Fixing file permissions..."
bash "$SCRIPT_DIR/permissions.sh" <<< "10"

header "Phase 6: Kernel Hardening"
info "Applying kernel security parameters..."
bash "$SCRIPT_DIR/kernel.sh" <<< "5"

# Calculate duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

header "Hardening Complete"
success "Full hardening completed in $DURATION seconds"

echo ""
echo "IMPORTANT POST-HARDENING STEPS:"
echo "1. Test SSH access in a NEW terminal before closing this one"
echo "2. Verify critical services are running"
echo "3. Check firewall allows required ports"
echo "4. Review /var/log/ccdc-toolkit/ for findings"
echo "5. Run persistence hunting: ../persistence-hunting/full-hunt.sh"
echo ""

log_action "Full system hardening completed"
