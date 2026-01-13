#!/bin/bash
# CCDC26 Linux Toolkit - Splunk Enterprise Server Setup
# Installs Splunk Enterprise (Free License - 500MB/day) for centralized log collection

source "$(dirname "$0")/../utils/common.sh"
require_root

header "Splunk Enterprise Server Setup"

#=============================================================================
# CONFIGURATION
#=============================================================================
SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
SPLUNK_VERSION="9.2.0"
SPLUNK_BUILD="2f6451c60e37"

# Splunk Enterprise download URLs
SPLUNK_DEB_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-2.6-amd64.deb"
SPLUNK_RPM_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}.x86_64.rpm"
SPLUNK_TGZ_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}-Linux-x86_64.tgz"

# Ports
WEB_PORT="8000"
MGMT_PORT="8089"
RECEIVE_PORT="9997"

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
# INSTALL SPLUNK ENTERPRISE
#=============================================================================
install_splunk() {
    header "Installing Splunk Enterprise"

    if [ -d "$SPLUNK_HOME" ] && [ -f "$SPLUNK_HOME/bin/splunk" ]; then
        info "Splunk Enterprise already installed at $SPLUNK_HOME"
        return 0
    fi

    local download_dir="/tmp/splunk-install"
    mkdir -p "$download_dir"
    cd "$download_dir"

    case "$PKG_MGR" in
        apt)
            info "Downloading Splunk Enterprise (DEB)..."
            wget -q --show-progress "$SPLUNK_DEB_URL" -O splunk.deb || {
                warn "Direct download failed, trying tarball..."
                install_tarball
                return
            }
            dpkg -i splunk.deb
            ;;
        dnf|yum)
            info "Downloading Splunk Enterprise (RPM)..."
            wget -q --show-progress "$SPLUNK_RPM_URL" -O splunk.rpm || {
                warn "Direct download failed, trying tarball..."
                install_tarball
                return
            }
            rpm -i splunk.rpm
            ;;
        *)
            install_tarball
            ;;
    esac

    rm -rf "$download_dir"
    success "Splunk Enterprise installed"
}

install_tarball() {
    info "Using tarball installation..."
    local download_dir="/tmp/splunk-install"
    mkdir -p "$download_dir"
    cd "$download_dir"

    wget -q --show-progress "$SPLUNK_TGZ_URL" -O splunk.tgz || {
        error "Failed to download Splunk Enterprise"
        error "Please download manually from: https://www.splunk.com/en_us/download/splunk-enterprise.html"
        exit 1
    }

    tar -xzf splunk.tgz -C /opt/
    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME"
    rm -rf "$download_dir"
    success "Splunk Enterprise installed via tarball"
}

#=============================================================================
# CONFIGURE RECEIVING (ACCEPT LOGS FROM FORWARDERS)
#=============================================================================
configure_receiving() {
    header "Configuring Data Receiving"

    local inputs_dir="$SPLUNK_HOME/etc/system/local"
    mkdir -p "$inputs_dir"

    cat > "$inputs_dir/inputs.conf" << EOF
# CCDC Splunk Server - Receiving Configuration
# Accept forwarded data on port $RECEIVE_PORT

[splunktcp://$RECEIVE_PORT]
disabled = false
connection_host = dns

EOF

    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$inputs_dir"
    success "Configured to receive data on port $RECEIVE_PORT"
}

#=============================================================================
# CREATE CCDC INDEXES
#=============================================================================
create_indexes() {
    header "Creating CCDC Indexes"

    local indexes_dir="$SPLUNK_HOME/etc/system/local"
    mkdir -p "$indexes_dir"

    cat > "$indexes_dir/indexes.conf" << EOF
# CCDC Custom Indexes
# Separate indexes for different log types

[main]
homePath = \$SPLUNK_DB/main/db
coldPath = \$SPLUNK_DB/main/colddb
thawedPath = \$SPLUNK_DB/main/thaweddb
maxTotalDataSizeMB = 5000

[security]
homePath = \$SPLUNK_DB/security/db
coldPath = \$SPLUNK_DB/security/colddb
thawedPath = \$SPLUNK_DB/security/thaweddb
maxTotalDataSizeMB = 5000

[os]
homePath = \$SPLUNK_DB/os/db
coldPath = \$SPLUNK_DB/os/colddb
thawedPath = \$SPLUNK_DB/os/thaweddb
maxTotalDataSizeMB = 3000

[web]
homePath = \$SPLUNK_DB/web/db
coldPath = \$SPLUNK_DB/web/colddb
thawedPath = \$SPLUNK_DB/web/thaweddb
maxTotalDataSizeMB = 3000

[database]
homePath = \$SPLUNK_DB/database/db
coldPath = \$SPLUNK_DB/database/colddb
thawedPath = \$SPLUNK_DB/database/thaweddb
maxTotalDataSizeMB = 2000

[mail]
homePath = \$SPLUNK_DB/mail/db
coldPath = \$SPLUNK_DB/mail/colddb
thawedPath = \$SPLUNK_DB/mail/thaweddb
maxTotalDataSizeMB = 2000

[dns]
homePath = \$SPLUNK_DB/dns/db
coldPath = \$SPLUNK_DB/dns/colddb
thawedPath = \$SPLUNK_DB/dns/thaweddb
maxTotalDataSizeMB = 2000

[ftp]
homePath = \$SPLUNK_DB/ftp/db
coldPath = \$SPLUNK_DB/ftp/colddb
thawedPath = \$SPLUNK_DB/ftp/thaweddb
maxTotalDataSizeMB = 1000

[ccdc]
homePath = \$SPLUNK_DB/ccdc/db
coldPath = \$SPLUNK_DB/ccdc/colddb
thawedPath = \$SPLUNK_DB/ccdc/thaweddb
maxTotalDataSizeMB = 2000

[containers]
homePath = \$SPLUNK_DB/containers/db
coldPath = \$SPLUNK_DB/containers/colddb
thawedPath = \$SPLUNK_DB/containers/thaweddb
maxTotalDataSizeMB = 2000

[wineventlog]
homePath = \$SPLUNK_DB/wineventlog/db
coldPath = \$SPLUNK_DB/wineventlog/colddb
thawedPath = \$SPLUNK_DB/wineventlog/thaweddb
maxTotalDataSizeMB = 5000

EOF

    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$indexes_dir"
    success "Created CCDC indexes"
}

#=============================================================================
# CONFIGURE WEB SETTINGS
#=============================================================================
configure_web() {
    header "Configuring Web Interface"

    local web_dir="$SPLUNK_HOME/etc/system/local"
    mkdir -p "$web_dir"

    cat > "$web_dir/web.conf" << EOF
# Splunk Web Configuration

[settings]
httpport = $WEB_PORT
enableSplunkWebSSL = false
startwebserver = true

EOF

    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$web_dir"
    success "Web interface configured on port $WEB_PORT"
}

#=============================================================================
# CONFIGURE SERVER SETTINGS
#=============================================================================
configure_server() {
    header "Configuring Server Settings"

    local server_dir="$SPLUNK_HOME/etc/system/local"
    mkdir -p "$server_dir"

    cat > "$server_dir/server.conf" << EOF
# Splunk Server Configuration

[general]
serverName = $(hostname)-splunk
pass4SymmKey = changeme

[license]
active_group = Free

[sslConfig]
enableSplunkdSSL = false

EOF

    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$server_dir"
    success "Server settings configured (Free license)"
}

#=============================================================================
# INITIAL SETUP
#=============================================================================
initial_setup() {
    header "Running Initial Splunk Setup"

    # Generate admin password
    local admin_password=$(generate_password 16)

    # Accept license and start
    "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt \
        --seed-passwd "$admin_password" 2>/dev/null

    "$SPLUNK_HOME/bin/splunk" stop 2>/dev/null

    # Enable boot-start
    "$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_USER" \
        --accept-license --answer-yes --no-prompt 2>/dev/null

    # Set ownership
    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME"

    success "Initial setup complete"
    echo ""
    warn "============================================"
    warn "SAVE THESE CREDENTIALS!"
    warn "============================================"
    echo "Admin Username: admin"
    echo "Admin Password: $admin_password"
    echo ""
    warn "Web Interface: http://$(hostname -I | awk '{print $1}'):$WEB_PORT"
    warn "============================================"

    # Save credentials to file
    echo "Admin Password: $admin_password" > "$SPLUNK_HOME/admin_credentials.txt"
    chmod 600 "$SPLUNK_HOME/admin_credentials.txt"
    info "Credentials saved to: $SPLUNK_HOME/admin_credentials.txt"
}

#=============================================================================
# START SPLUNK
#=============================================================================
start_splunk() {
    header "Starting Splunk Enterprise"

    su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk start" 2>/dev/null || \
        "$SPLUNK_HOME/bin/splunk" start 2>/dev/null

    sleep 5

    if pgrep -f "splunkd" > /dev/null; then
        success "Splunk Enterprise is running"
        "$SPLUNK_HOME/bin/splunk" status
    else
        error "Splunk failed to start"
        return 1
    fi
}

#=============================================================================
# CONFIGURE FIREWALL
#=============================================================================
configure_firewall() {
    header "Configuring Firewall"

    case "$FIREWALL" in
        ufw)
            ufw allow $WEB_PORT/tcp comment "Splunk Web"
            ufw allow $MGMT_PORT/tcp comment "Splunk Management"
            ufw allow $RECEIVE_PORT/tcp comment "Splunk Receiving"
            ;;
        firewalld)
            firewall-cmd --permanent --add-port=$WEB_PORT/tcp
            firewall-cmd --permanent --add-port=$MGMT_PORT/tcp
            firewall-cmd --permanent --add-port=$RECEIVE_PORT/tcp
            firewall-cmd --reload
            ;;
        iptables)
            iptables -A INPUT -p tcp --dport $WEB_PORT -j ACCEPT
            iptables -A INPUT -p tcp --dport $MGMT_PORT -j ACCEPT
            iptables -A INPUT -p tcp --dport $RECEIVE_PORT -j ACCEPT
            ;;
    esac

    success "Firewall configured for Splunk ports"
}

#=============================================================================
# CHECK STATUS
#=============================================================================
check_status() {
    header "Splunk Server Status"

    if [ ! -f "$SPLUNK_HOME/bin/splunk" ]; then
        error "Splunk Enterprise not installed"
        return 1
    fi

    "$SPLUNK_HOME/bin/splunk" status

    echo ""
    info "Ports:"
    echo "  Web Interface: $WEB_PORT"
    echo "  Management: $MGMT_PORT"
    echo "  Receiving: $RECEIVE_PORT"

    echo ""
    info "Connected Forwarders:"
    "$SPLUNK_HOME/bin/splunk" list forward-server 2>/dev/null || \
        echo "  (Run from Splunk CLI to see forwarders)"

    echo ""
    info "License Status:"
    "$SPLUNK_HOME/bin/splunk" list licenses 2>/dev/null | head -10

    echo ""
    info "Indexes:"
    "$SPLUNK_HOME/bin/splunk" list index 2>/dev/null | grep -E "^[a-z]" | head -15
}

#=============================================================================
# QUICK SETUP
#=============================================================================
quick_setup() {
    header "Quick Setup - Full Installation"

    create_splunk_user
    install_splunk
    configure_server
    configure_receiving
    create_indexes
    configure_web
    initial_setup
    configure_firewall
    start_splunk

    echo ""
    success "============================================"
    success "Splunk Enterprise Setup Complete!"
    success "============================================"
    echo ""
    info "Web Interface: http://$(hostname -I | awk '{print $1}'):$WEB_PORT"
    info "Receiving Port: $RECEIVE_PORT"
    echo ""
    info "Configure your forwarders to send to this server:"
    echo "  SPLUNK_SERVER=\"$(hostname -I | awk '{print $1}')\""
    echo "  SPLUNK_PORT=\"$RECEIVE_PORT\""
    echo ""
    warn "Free license limit: 500 MB/day"
    warn "If you exceed this, data will queue until the next day"

    log_action "Installed Splunk Enterprise server"
}

#=============================================================================
# MAIN MENU
#=============================================================================
main() {
    echo ""
    echo "Splunk Enterprise Server Options:"
    echo "1) Quick setup (full installation)"
    echo "2) Check status"
    echo "3) Start Splunk"
    echo "4) Stop Splunk"
    echo "5) Restart Splunk"
    echo "6) View admin credentials"
    echo "7) Configure firewall"
    echo "8) View recent logs"
    echo ""
    read -p "Select option [1-8]: " choice

    case $choice in
        1) quick_setup ;;
        2) check_status ;;
        3) "$SPLUNK_HOME/bin/splunk" start ;;
        4) "$SPLUNK_HOME/bin/splunk" stop ;;
        5) "$SPLUNK_HOME/bin/splunk" restart ;;
        6) cat "$SPLUNK_HOME/admin_credentials.txt" 2>/dev/null || error "Credentials file not found" ;;
        7) configure_firewall ;;
        8) tail -100 "$SPLUNK_HOME/var/log/splunk/splunkd.log" 2>/dev/null ;;
        *) error "Invalid option" ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
