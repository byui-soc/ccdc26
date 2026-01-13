#!/bin/bash
# Brady Hodge / CCDC26 Linux Toolkit - Splunk Universal Forwarder Setup
# Deploys and configures Splunk UF to forward all logs to central Splunk server

source "$(dirname "$0")/../utils/common.sh"
require_root

header "Splunk Universal Forwarder Setup"

#=============================================================================
# CONFIGURATION - UPDATE THESE VALUES FOR YOUR ENVIRONMENT
#=============================================================================
# Splunk Indexer/Receiver settings
SPLUNK_SERVER="CHANGE_ME"           # IP or hostname of Splunk indexer
SPLUNK_PORT="9997"                   # Default receiving port
SPLUNK_MGMT_PORT="8089"              # Management port (for deployment server)

# Deployment Server (optional - leave empty if not using)
DEPLOYMENT_SERVER=""                 # IP or hostname of deployment server
DEPLOYMENT_PORT="8089"

# Forwarder settings
SPLUNK_HOME="/opt/splunkforwarder"
SPLUNK_USER="splunk"
SPLUNK_VERSION="9.2.0"               # Update to latest version
SPLUNK_BUILD="2f6451c60e37"          # Update with version

# Download URL (update based on version)
SPLUNK_DEB_URL="https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/linux/splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-2.6-amd64.deb"
SPLUNK_RPM_URL="https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/linux/splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}.x86_64.rpm"
SPLUNK_TGZ_URL="https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/linux/splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-Linux-x86_64.tgz"

#=============================================================================
# VALIDATION
#=============================================================================
validate_config() {
    if [ "$SPLUNK_SERVER" = "CHANGE_ME" ]; then
        error "SPLUNK_SERVER is not configured!"
        error "Edit this script and set SPLUNK_SERVER to your Splunk indexer IP/hostname"
        info "Example: SPLUNK_SERVER=\"192.168.1.100\" or SPLUNK_SERVER=\"splunk.local\""
        exit 1
    fi
}

#=============================================================================
# CREATE SPLUNK USER
#=============================================================================
create_splunk_user() {
    header "Creating Splunk User"

    if id "$SPLUNK_USER" &>/dev/null; then
        info "User $SPLUNK_USER already exists"
    else
        useradd -r -m -d "$SPLUNK_HOME" -s /bin/bash "$SPLUNK_USER"
        success "Created user: $SPLUNK_USER"
    fi
}

#=============================================================================
# DOWNLOAD AND INSTALL SPLUNK FORWARDER
#=============================================================================
install_splunk_forwarder() {
    header "Installing Splunk Universal Forwarder"

    if [ -d "$SPLUNK_HOME" ] && [ -f "$SPLUNK_HOME/bin/splunk" ]; then
        info "Splunk Forwarder already installed at $SPLUNK_HOME"
        return 0
    fi

    local download_dir="/tmp/splunk-install"
    mkdir -p "$download_dir"
    cd "$download_dir"

    case "$PKG_MGR" in
        apt)
            info "Downloading Splunk Forwarder (DEB)..."
            wget -q "$SPLUNK_DEB_URL" -O splunkforwarder.deb || {
                warn "Direct download failed, trying alternative method..."
                download_alternative
                return
            }
            dpkg -i splunkforwarder.deb
            ;;
        dnf|yum)
            info "Downloading Splunk Forwarder (RPM)..."
            wget -q "$SPLUNK_RPM_URL" -O splunkforwarder.rpm || {
                warn "Direct download failed, trying alternative method..."
                download_alternative
                return
            }
            rpm -i splunkforwarder.rpm
            ;;
        *)
            download_alternative
            ;;
    esac

    rm -rf "$download_dir"
    success "Splunk Forwarder installed"
}

download_alternative() {
    info "Using tarball installation method..."
    local download_dir="/tmp/splunk-install"
    mkdir -p "$download_dir"
    cd "$download_dir"

    wget -q "$SPLUNK_TGZ_URL" -O splunkforwarder.tgz || {
        error "Failed to download Splunk Forwarder"
        error "Please download manually from: https://www.splunk.com/en_us/download/universal-forwarder.html"
        exit 1
    }

    tar -xzf splunkforwarder.tgz -C /opt/
    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME"
    rm -rf "$download_dir"
    success "Splunk Forwarder installed via tarball"
}

#=============================================================================
# CONFIGURE OUTPUTS (WHERE TO SEND LOGS)
#=============================================================================
configure_outputs() {
    header "Configuring Splunk Outputs"

    local outputs_dir="$SPLUNK_HOME/etc/system/local"
    mkdir -p "$outputs_dir"

    cat > "$outputs_dir/outputs.conf" << EOF
# CCDC Splunk Forwarder Outputs Configuration
# Generated: $(date)

[tcpout]
defaultGroup = ccdc-indexers

[tcpout:ccdc-indexers]
server = ${SPLUNK_SERVER}:${SPLUNK_PORT}
compressed = true
useACK = true

# SSL Configuration (uncomment if using SSL)
# sslCertPath = \$SPLUNK_HOME/etc/auth/server.pem
# sslPassword = password
# sslRootCAPath = \$SPLUNK_HOME/etc/auth/cacert.pem
# sslVerifyServerCert = false

# Retry settings for reliability
autoLBFrequency = 30
autoLBVolume = 1048576
forceTimebasedAutoLB = true

EOF

    # Add deployment server config if specified
    if [ -n "$DEPLOYMENT_SERVER" ]; then
        cat > "$outputs_dir/deploymentclient.conf" << EOF
# Deployment Server Configuration
[deployment-client]

[target-broker:deploymentServer]
targetUri = ${DEPLOYMENT_SERVER}:${DEPLOYMENT_PORT}
EOF
        success "Deployment server configured: $DEPLOYMENT_SERVER:$DEPLOYMENT_PORT"
    fi

    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$outputs_dir"
    success "Outputs configured: $SPLUNK_SERVER:$SPLUNK_PORT"
}

#=============================================================================
# CONFIGURE INPUTS (WHAT LOGS TO COLLECT)
#=============================================================================
configure_inputs() {
    header "Configuring Splunk Inputs"

    local inputs_dir="$SPLUNK_HOME/etc/system/local"
    mkdir -p "$inputs_dir"

    # Detect hostname for source tagging
    local hostname=$(hostname)

    cat > "$inputs_dir/inputs.conf" << EOF
# CCDC Splunk Forwarder Inputs Configuration
# Generated: $(date)
# Host: ${hostname}

#=============================================================================
# GLOBAL SETTINGS
#=============================================================================
[default]
host = ${hostname}
index = main

#=============================================================================
# AUTHENTICATION LOGS - Critical for security monitoring
#=============================================================================
[monitor:///var/log/auth.log]
disabled = false
sourcetype = linux_secure
index = security

[monitor:///var/log/secure]
disabled = false
sourcetype = linux_secure
index = security

#=============================================================================
# SYSTEM LOGS
#=============================================================================
[monitor:///var/log/syslog]
disabled = false
sourcetype = syslog
index = os

[monitor:///var/log/messages]
disabled = false
sourcetype = syslog
index = os

[monitor:///var/log/kern.log]
disabled = false
sourcetype = linux_kernel
index = os

[monitor:///var/log/dmesg]
disabled = false
sourcetype = dmesg
index = os

#=============================================================================
# AUDIT LOGS - Critical for compliance and forensics
#=============================================================================
[monitor:///var/log/audit/audit.log]
disabled = false
sourcetype = linux_audit
index = security

#=============================================================================
# APACHE WEB SERVER LOGS
#=============================================================================
[monitor:///var/log/apache2/access.log]
disabled = false
sourcetype = access_combined
index = web

[monitor:///var/log/apache2/error.log]
disabled = false
sourcetype = apache_error
index = web

[monitor:///var/log/apache2/*/access.log]
disabled = false
sourcetype = access_combined
index = web

[monitor:///var/log/apache2/*/error.log]
disabled = false
sourcetype = apache_error
index = web

# RHEL/CentOS Apache paths
[monitor:///var/log/httpd/access_log]
disabled = false
sourcetype = access_combined
index = web

[monitor:///var/log/httpd/error_log]
disabled = false
sourcetype = apache_error
index = web

[monitor:///var/log/httpd/*/access_log]
disabled = false
sourcetype = access_combined
index = web

[monitor:///var/log/httpd/*/error_log]
disabled = false
sourcetype = apache_error
index = web

#=============================================================================
# NGINX WEB SERVER LOGS
#=============================================================================
[monitor:///var/log/nginx/access.log]
disabled = false
sourcetype = nginx_access
index = web

[monitor:///var/log/nginx/error.log]
disabled = false
sourcetype = nginx_error
index = web

[monitor:///var/log/nginx/*/access.log]
disabled = false
sourcetype = nginx_access
index = web

[monitor:///var/log/nginx/*/error.log]
disabled = false
sourcetype = nginx_error
index = web

#=============================================================================
# DATABASE LOGS
#=============================================================================
# MySQL/MariaDB
[monitor:///var/log/mysql/error.log]
disabled = false
sourcetype = mysql_error
index = database

[monitor:///var/log/mysql/mysql.log]
disabled = false
sourcetype = mysql_general
index = database

[monitor:///var/log/mysql/mysql-slow.log]
disabled = false
sourcetype = mysql_slow
index = database

[monitor:///var/log/mariadb/mariadb.log]
disabled = false
sourcetype = mysql_error
index = database

# PostgreSQL
[monitor:///var/log/postgresql/postgresql-*.log]
disabled = false
sourcetype = postgresql
index = database

[monitor:///var/log/postgresql/*.log]
disabled = false
sourcetype = postgresql
index = database

#=============================================================================
# MAIL SERVER LOGS
#=============================================================================
[monitor:///var/log/mail.log]
disabled = false
sourcetype = syslog
index = mail

[monitor:///var/log/mail.err]
disabled = false
sourcetype = syslog
index = mail

[monitor:///var/log/maillog]
disabled = false
sourcetype = syslog
index = mail

#=============================================================================
# DNS SERVER LOGS
#=============================================================================
[monitor:///var/log/named/queries.log]
disabled = false
sourcetype = named
index = dns

[monitor:///var/log/named/security.log]
disabled = false
sourcetype = named
index = dns

[monitor:///var/log/bind/query.log]
disabled = false
sourcetype = named
index = dns

#=============================================================================
# FTP SERVER LOGS
#=============================================================================
[monitor:///var/log/vsftpd.log]
disabled = false
sourcetype = vsftpd
index = ftp

[monitor:///var/log/proftpd/proftpd.log]
disabled = false
sourcetype = proftpd
index = ftp

[monitor:///var/log/xferlog]
disabled = false
sourcetype = xferlog
index = ftp

#=============================================================================
# SSH LOGS
#=============================================================================
[monitor:///var/log/ssh/sshd.log]
disabled = false
sourcetype = sshd
index = security

#=============================================================================
# FAIL2BAN LOGS
#=============================================================================
[monitor:///var/log/fail2ban.log]
disabled = false
sourcetype = fail2ban
index = security

#=============================================================================
# CRON LOGS
#=============================================================================
[monitor:///var/log/cron]
disabled = false
sourcetype = cron
index = os

[monitor:///var/log/cron.log]
disabled = false
sourcetype = cron
index = os

#=============================================================================
# PACKAGE MANAGER LOGS
#=============================================================================
[monitor:///var/log/apt/history.log]
disabled = false
sourcetype = apt
index = os

[monitor:///var/log/apt/term.log]
disabled = false
sourcetype = apt
index = os

[monitor:///var/log/dpkg.log]
disabled = false
sourcetype = dpkg
index = os

[monitor:///var/log/yum.log]
disabled = false
sourcetype = yum
index = os

[monitor:///var/log/dnf.log]
disabled = false
sourcetype = yum
index = os

#=============================================================================
# CCDC TOOLKIT LOGS - Our own monitoring output
#=============================================================================
[monitor:///var/log/ccdc-toolkit/actions.log]
disabled = false
sourcetype = ccdc_actions
index = ccdc

[monitor:///var/log/ccdc-toolkit/findings.log]
disabled = false
sourcetype = ccdc_findings
index = ccdc

[monitor:///var/log/ccdc-toolkit/file-monitor.log]
disabled = false
sourcetype = ccdc_file_monitor
index = ccdc

[monitor:///var/log/ccdc-toolkit/process-monitor.log]
disabled = false
sourcetype = ccdc_process_monitor
index = ccdc

[monitor:///var/log/ccdc-toolkit/network-monitor.log]
disabled = false
sourcetype = ccdc_network_monitor
index = ccdc

[monitor:///var/log/ccdc-toolkit/log-watcher.log]
disabled = false
sourcetype = ccdc_log_watcher
index = ccdc

#=============================================================================
# SECURITY TOOL LOGS
#=============================================================================
[monitor:///var/log/rkhunter.log]
disabled = false
sourcetype = rkhunter
index = security

[monitor:///var/log/clamav/clamav.log]
disabled = false
sourcetype = clamav
index = security

[monitor:///var/log/aide/aide.log]
disabled = false
sourcetype = aide
index = security

#=============================================================================
# DOCKER LOGS (if present)
#=============================================================================
[monitor:///var/lib/docker/containers/*/*-json.log]
disabled = false
sourcetype = docker_json
index = containers

#=============================================================================
# SYSTEMD JOURNAL (optional - uses scripted input)
#=============================================================================
# Uncomment below to forward journald logs
# [script://./bin/scripts/journald_input.sh]
# disabled = false
# interval = 60
# sourcetype = journald
# index = os

EOF

    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$inputs_dir"
    success "Inputs configured for all major log sources"
}

#=============================================================================
# CONFIGURE ADDITIONAL SETTINGS
#=============================================================================
configure_settings() {
    header "Configuring Additional Settings"

    local config_dir="$SPLUNK_HOME/etc/system/local"

    # Server settings
    cat > "$config_dir/server.conf" << EOF
# CCDC Splunk Forwarder Server Configuration

[general]
serverName = $(hostname)

[sslConfig]
enableSplunkdSSL = false

EOF

    # Web settings (disable web interface on forwarder)
    cat > "$config_dir/web.conf" << EOF
# Disable web interface on forwarder

[settings]
enableSplunkWebSSL = false
startwebserver = false

EOF

    # Limits (increase for high-volume environments)
    cat > "$config_dir/limits.conf" << EOF
# CCDC Performance Settings

[thruput]
maxKBps = 0

[inputproc]
max_fd = 10000

EOF

    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$config_dir"
    success "Additional settings configured"
}

#=============================================================================
# INITIAL SPLUNK SETUP
#=============================================================================
initial_setup() {
    header "Running Initial Splunk Setup"

    # Accept license and set admin password
    local admin_password=$(generate_password 16)

    "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt \
        --seed-passwd "$admin_password" 2>/dev/null

    "$SPLUNK_HOME/bin/splunk" stop 2>/dev/null

    # Enable boot-start
    "$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_USER" --accept-license --answer-yes --no-prompt 2>/dev/null

    # Set ownership
    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME"

    success "Initial setup complete"
    info "Admin password: $admin_password (save this!)"
}

#=============================================================================
# START SPLUNK FORWARDER
#=============================================================================
start_forwarder() {
    header "Starting Splunk Forwarder"

    # Start as splunk user
    su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk start" 2>/dev/null || \
        "$SPLUNK_HOME/bin/splunk" start 2>/dev/null

    # Check status
    sleep 3
    if pgrep -f "splunkd" > /dev/null; then
        success "Splunk Forwarder is running"
        "$SPLUNK_HOME/bin/splunk" status
    else
        error "Splunk Forwarder failed to start"
        "$SPLUNK_HOME/bin/splunk" status
        return 1
    fi
}

#=============================================================================
# STATUS CHECK
#=============================================================================
check_status() {
    header "Splunk Forwarder Status"

    if [ ! -f "$SPLUNK_HOME/bin/splunk" ]; then
        error "Splunk Forwarder not installed"
        return 1
    fi

    "$SPLUNK_HOME/bin/splunk" status

    echo ""
    info "Forwarding to: $SPLUNK_SERVER:$SPLUNK_PORT"

    echo ""
    info "Log inputs configured:"
    grep "^\[monitor" "$SPLUNK_HOME/etc/system/local/inputs.conf" 2>/dev/null | head -20

    echo ""
    info "Recent forwarding activity:"
    tail -20 "$SPLUNK_HOME/var/log/splunk/splunkd.log" 2>/dev/null | grep -iE "(connected|forwarding|sending)"
}

#=============================================================================
# TEST CONNECTIVITY
#=============================================================================
test_connectivity() {
    header "Testing Splunk Server Connectivity"

    validate_config

    info "Testing connection to $SPLUNK_SERVER:$SPLUNK_PORT..."

    if command -v nc &>/dev/null; then
        if nc -zv "$SPLUNK_SERVER" "$SPLUNK_PORT" 2>&1 | grep -q "succeeded\|open"; then
            success "Connection to $SPLUNK_SERVER:$SPLUNK_PORT successful"
        else
            error "Cannot connect to $SPLUNK_SERVER:$SPLUNK_PORT"
            warn "Ensure the Splunk indexer is running and port $SPLUNK_PORT is open"
        fi
    elif command -v timeout &>/dev/null; then
        if timeout 5 bash -c "echo > /dev/tcp/$SPLUNK_SERVER/$SPLUNK_PORT" 2>/dev/null; then
            success "Connection to $SPLUNK_SERVER:$SPLUNK_PORT successful"
        else
            error "Cannot connect to $SPLUNK_SERVER:$SPLUNK_PORT"
        fi
    else
        warn "Cannot test connectivity (nc/timeout not available)"
    fi
}

#=============================================================================
# UNINSTALL
#=============================================================================
uninstall_forwarder() {
    header "Uninstalling Splunk Forwarder"

    read -p "Are you sure you want to uninstall? [y/N] " confirm
    [[ "$confirm" != [yY] ]] && return

    # Stop service
    "$SPLUNK_HOME/bin/splunk" stop 2>/dev/null

    # Disable boot-start
    "$SPLUNK_HOME/bin/splunk" disable boot-start 2>/dev/null

    # Remove systemd service
    rm -f /etc/systemd/system/SplunkForwarder.service
    systemctl daemon-reload 2>/dev/null

    # Remove installation
    rm -rf "$SPLUNK_HOME"

    # Remove user
    userdel "$SPLUNK_USER" 2>/dev/null

    success "Splunk Forwarder uninstalled"
}

#=============================================================================
# QUICK SETUP (FULL INSTALLATION)
#=============================================================================
quick_setup() {
    header "Quick Setup - Full Installation"

    validate_config
    create_splunk_user
    install_splunk_forwarder
    configure_outputs
    configure_inputs
    configure_settings
    initial_setup
    start_forwarder

    echo ""
    success "============================================"
    success "Splunk Universal Forwarder Setup Complete!"
    success "============================================"
    echo ""
    info "Forwarding to: $SPLUNK_SERVER:$SPLUNK_PORT"
    info "Logs directory: $SPLUNK_HOME/var/log/splunk/"
    info "Config directory: $SPLUNK_HOME/etc/system/local/"
    echo ""
    warn "Remember to create these indexes on your Splunk server:"
    echo "  - main (default)"
    echo "  - security (auth, audit, fail2ban logs)"
    echo "  - os (system logs)"
    echo "  - web (apache, nginx logs)"
    echo "  - database (mysql, postgresql logs)"
    echo "  - mail (mail server logs)"
    echo "  - dns (bind/named logs)"
    echo "  - ftp (ftp server logs)"
    echo "  - ccdc (toolkit logs)"
    echo "  - containers (docker logs)"

    log_action "Installed Splunk Universal Forwarder -> $SPLUNK_SERVER:$SPLUNK_PORT"
}

#=============================================================================
# RECONFIGURE (UPDATE SERVER/INPUTS)
#=============================================================================
reconfigure() {
    header "Reconfigure Splunk Forwarder"

    echo "Current configuration:"
    echo "  Server: $SPLUNK_SERVER:$SPLUNK_PORT"
    echo ""

    read -p "Enter new Splunk server IP/hostname (or press Enter to keep current): " new_server
    [ -n "$new_server" ] && SPLUNK_SERVER="$new_server"

    read -p "Enter new port (or press Enter for $SPLUNK_PORT): " new_port
    [ -n "$new_port" ] && SPLUNK_PORT="$new_port"

    configure_outputs

    "$SPLUNK_HOME/bin/splunk" restart

    success "Reconfigured to forward to $SPLUNK_SERVER:$SPLUNK_PORT"
}

#=============================================================================
# MAIN MENU
#=============================================================================
main() {
    echo ""
    echo "Splunk Universal Forwarder Options:"
    echo "1) Quick setup (full installation)"
    echo "2) Check status"
    echo "3) Test server connectivity"
    echo "4) Reconfigure server/port"
    echo "5) View recent logs"
    echo "6) Restart forwarder"
    echo "7) Stop forwarder"
    echo "8) Uninstall"
    echo ""
    read -p "Select option [1-8]: " choice

    case $choice in
        1) quick_setup ;;
        2) check_status ;;
        3) test_connectivity ;;
        4) reconfigure ;;
        5) tail -50 "$SPLUNK_HOME/var/log/splunk/splunkd.log" 2>/dev/null ;;
        6) "$SPLUNK_HOME/bin/splunk" restart ;;
        7) "$SPLUNK_HOME/bin/splunk" stop ;;
        8) uninstall_forwarder ;;
        *) error "Invalid option" ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
