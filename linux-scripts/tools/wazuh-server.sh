#!/bin/bash
# CCDC26 Linux Toolkit - Wazuh Server (All-in-One) Setup
# Installs Wazuh Manager, Indexer, and Dashboard for centralized security monitoring
# Recommended: 8GB RAM, 4 CPU cores, 50GB disk

source "$(dirname "$0")/../utils/common.sh"
require_root

header "Wazuh Server Setup (All-in-One)"

#=============================================================================
# CONFIGURATION
#=============================================================================
WAZUH_VERSION="4.7.2"
WAZUH_DIR="/var/ossec"
INDEXER_DIR="/etc/wazuh-indexer"
DASHBOARD_DIR="/etc/wazuh-dashboard"

# Network
WAZUH_MANAGER_IP=""  # Will be auto-detected or set manually
INDEXER_PORT="9200"
DASHBOARD_PORT="443"
AGENT_PORT="1514"
ENROLLMENT_PORT="1515"
API_PORT="55000"

# Credentials (will be generated)
ADMIN_PASSWORD=""
API_PASSWORD=""

#=============================================================================
# SYSTEM REQUIREMENTS CHECK
#=============================================================================
check_requirements() {
    header "Checking System Requirements"

    # Check RAM (minimum 4GB, recommended 8GB)
    local total_ram=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_ram" -lt 4 ]; then
        error "Insufficient RAM: ${total_ram}GB (minimum 4GB, recommended 8GB)"
        exit 1
    elif [ "$total_ram" -lt 8 ]; then
        warn "RAM: ${total_ram}GB (8GB+ recommended for production)"
    else
        success "RAM: ${total_ram}GB"
    fi

    # Check disk space (minimum 20GB free)
    local free_disk=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')
    if [ "$free_disk" -lt 20 ]; then
        error "Insufficient disk space: ${free_disk}GB free (minimum 20GB)"
        exit 1
    else
        success "Disk: ${free_disk}GB free"
    fi

    # Check CPU cores
    local cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 2 ]; then
        warn "CPU cores: $cpu_cores (4+ recommended)"
    else
        success "CPU cores: $cpu_cores"
    fi

    # Check for supported distro
    case "$DISTRO_FAMILY" in
        debian|rhel)
            success "Distribution: $DISTRO_ID ($DISTRO_FAMILY)"
            ;;
        *)
            error "Unsupported distribution: $DISTRO_ID"
            info "Wazuh server requires Debian/Ubuntu or RHEL/CentOS"
            exit 1
            ;;
    esac

    # Detect IP address
    WAZUH_MANAGER_IP=$(hostname -I | awk '{print $1}')
    info "Server IP: $WAZUH_MANAGER_IP"
}

#=============================================================================
# GENERATE PASSWORDS
#=============================================================================
generate_passwords() {
    header "Generating Secure Passwords"

    ADMIN_PASSWORD=$(generate_password 24)
    API_PASSWORD=$(generate_password 24)

    # Save passwords securely
    mkdir -p /root/.wazuh
    chmod 700 /root/.wazuh

    cat > /root/.wazuh/credentials.txt << EOF
# Wazuh Credentials - Generated $(date)
# KEEP THIS FILE SECURE!

Dashboard Admin:
  Username: admin
  Password: $ADMIN_PASSWORD
  URL: https://$WAZUH_MANAGER_IP:$DASHBOARD_PORT

Wazuh API:
  Username: wazuh
  Password: $API_PASSWORD
  URL: https://$WAZUH_MANAGER_IP:$API_PORT

Agent Enrollment:
  Manager IP: $WAZUH_MANAGER_IP
  Port: $AGENT_PORT (events), $ENROLLMENT_PORT (registration)
EOF

    chmod 600 /root/.wazuh/credentials.txt
    success "Credentials saved to /root/.wazuh/credentials.txt"
}

#=============================================================================
# ADD WAZUH REPOSITORY
#=============================================================================
add_wazuh_repo() {
    header "Adding Wazuh Repository"

    case "$DISTRO_FAMILY" in
        debian)
            apt-get update
            apt-get install -y curl apt-transport-https gnupg2

            curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list

            apt-get update
            success "Wazuh repository added (Debian/Ubuntu)"
            ;;

        rhel)
            rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

            cat > /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
protect=1
EOF
            success "Wazuh repository added (RHEL/CentOS)"
            ;;
    esac
}

#=============================================================================
# INSTALL WAZUH INDEXER
#=============================================================================
install_indexer() {
    header "Installing Wazuh Indexer"

    # Install package
    case "$DISTRO_FAMILY" in
        debian)
            apt-get install -y wazuh-indexer
            ;;
        rhel)
            $PKG_MGR install -y wazuh-indexer
            ;;
    esac

    # Configure indexer
    local config_file="/etc/wazuh-indexer/opensearch.yml"

    backup_file "$config_file"

    cat > "$config_file" << EOF
# Wazuh Indexer Configuration (OpenSearch)
# CCDC26 Configuration

network.host: "0.0.0.0"
node.name: "wazuh-indexer"
cluster.name: "wazuh-cluster"
cluster.initial_master_nodes:
  - "wazuh-indexer"

path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/wazuh-indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem

plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/wazuh-indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

plugins.security.nodes_dn:
  - "CN=wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US"
plugins.security.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US"

plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US"

plugins.security.allow_default_init_securityindex: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]

compatibility.override_main_response_version: true
EOF

    # Generate certificates using wazuh-certs-tool
    info "Generating SSL certificates..."

    # Create config.yml for cert generation
    mkdir -p /tmp/wazuh-certs
    cat > /tmp/wazuh-certs/config.yml << EOF
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "$WAZUH_MANAGER_IP"
  server:
    - name: wazuh-manager
      ip: "$WAZUH_MANAGER_IP"
  dashboard:
    - name: wazuh-dashboard
      ip: "$WAZUH_MANAGER_IP"
EOF

    # Download and run certificate tool
    cd /tmp/wazuh-certs
    curl -sO https://packages.wazuh.com/4.7/wazuh-certs-tool.sh
    chmod +x wazuh-certs-tool.sh
    ./wazuh-certs-tool.sh -A

    # Deploy indexer certificates
    mkdir -p /etc/wazuh-indexer/certs
    cp wazuh-certificates/wazuh-indexer.pem /etc/wazuh-indexer/certs/
    cp wazuh-certificates/wazuh-indexer-key.pem /etc/wazuh-indexer/certs/
    cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/
    cp wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/
    cp wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/

    chmod 500 /etc/wazuh-indexer/certs
    chmod 400 /etc/wazuh-indexer/certs/*
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

    # Start indexer
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer

    # Wait for startup
    info "Waiting for indexer to start..."
    sleep 30

    # Initialize security plugin
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh

    success "Wazuh Indexer installed and configured"
}

#=============================================================================
# INSTALL WAZUH MANAGER
#=============================================================================
install_manager() {
    header "Installing Wazuh Manager"

    # Install package
    case "$DISTRO_FAMILY" in
        debian)
            apt-get install -y wazuh-manager
            ;;
        rhel)
            $PKG_MGR install -y wazuh-manager
            ;;
    esac

    # Configure manager
    backup_file "$WAZUH_DIR/etc/ossec.conf"

    # Enable authd for auto-enrollment
    cat > "$WAZUH_DIR/etc/authd.pass" << EOF
$API_PASSWORD
EOF
    chmod 640 "$WAZUH_DIR/etc/authd.pass"
    chown root:wazuh "$WAZUH_DIR/etc/authd.pass"

    # Start manager
    systemctl daemon-reload
    systemctl enable wazuh-manager
    systemctl start wazuh-manager

    success "Wazuh Manager installed"
}

#=============================================================================
# INSTALL FILEBEAT (connects Manager to Indexer)
#=============================================================================
install_filebeat() {
    header "Installing Filebeat"

    # Install Filebeat
    case "$DISTRO_FAMILY" in
        debian)
            apt-get install -y filebeat
            ;;
        rhel)
            $PKG_MGR install -y filebeat
            ;;
    esac

    # Download Wazuh Filebeat module
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v$WAZUH_VERSION/extensions/elasticsearch/7.x/wazuh-template.json
    chmod go+r /etc/filebeat/wazuh-template.json

    curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.3.tar.gz | tar -xvz -C /usr/share/filebeat/module

    # Configure Filebeat
    cat > /etc/filebeat/filebeat.yml << EOF
# Wazuh Filebeat Configuration

output.elasticsearch:
  hosts: ["https://127.0.0.1:9200"]
  protocol: https
  username: admin
  password: admin
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: /etc/filebeat/certs/wazuh-manager.pem
  ssl.key: /etc/filebeat/certs/wazuh-manager-key.pem

setup.template.json.enabled: true
setup.template.json.path: /etc/filebeat/wazuh-template.json
setup.template.json.name: wazuh
setup.template.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false
EOF

    # Deploy Filebeat certificates
    mkdir -p /etc/filebeat/certs
    cp /tmp/wazuh-certs/wazuh-certificates/wazuh-manager.pem /etc/filebeat/certs/
    cp /tmp/wazuh-certs/wazuh-certificates/wazuh-manager-key.pem /etc/filebeat/certs/
    cp /tmp/wazuh-certs/wazuh-certificates/root-ca.pem /etc/filebeat/certs/

    chmod 500 /etc/filebeat/certs
    chmod 400 /etc/filebeat/certs/*
    chown -R root:root /etc/filebeat/certs

    # Start Filebeat
    systemctl daemon-reload
    systemctl enable filebeat
    systemctl start filebeat

    success "Filebeat installed and configured"
}

#=============================================================================
# INSTALL WAZUH DASHBOARD
#=============================================================================
install_dashboard() {
    header "Installing Wazuh Dashboard"

    # Install package
    case "$DISTRO_FAMILY" in
        debian)
            apt-get install -y wazuh-dashboard
            ;;
        rhel)
            $PKG_MGR install -y wazuh-dashboard
            ;;
    esac

    # Configure dashboard
    local config_file="/etc/wazuh-dashboard/opensearch_dashboards.yml"

    backup_file "$config_file"

    cat > "$config_file" << EOF
# Wazuh Dashboard Configuration

server.host: "0.0.0.0"
server.port: 443
opensearch.hosts: ["https://127.0.0.1:9200"]
opensearch.ssl.verificationMode: certificate
opensearch.username: kibanaserver
opensearch.password: kibanaserver
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
server.ssl.enabled: true
server.ssl.key: "/etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/etc/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
uiSettings.overrides.defaultRoute: /app/wazuh
EOF

    # Deploy dashboard certificates
    mkdir -p /etc/wazuh-dashboard/certs
    cp /tmp/wazuh-certs/wazuh-certificates/wazuh-dashboard.pem /etc/wazuh-dashboard/certs/
    cp /tmp/wazuh-certs/wazuh-certificates/wazuh-dashboard-key.pem /etc/wazuh-dashboard/certs/
    cp /tmp/wazuh-certs/wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/

    chmod 500 /etc/wazuh-dashboard/certs
    chmod 400 /etc/wazuh-dashboard/certs/*
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

    # Start dashboard
    systemctl daemon-reload
    systemctl enable wazuh-dashboard
    systemctl start wazuh-dashboard

    success "Wazuh Dashboard installed"
}

#=============================================================================
# CONFIGURE FIREWALL
#=============================================================================
configure_firewall() {
    header "Configuring Firewall"

    case "$FIREWALL" in
        ufw)
            ufw allow $DASHBOARD_PORT/tcp comment "Wazuh Dashboard"
            ufw allow $AGENT_PORT/tcp comment "Wazuh Agent Events"
            ufw allow $ENROLLMENT_PORT/tcp comment "Wazuh Agent Enrollment"
            ufw allow $API_PORT/tcp comment "Wazuh API"
            ufw allow $INDEXER_PORT/tcp comment "Wazuh Indexer"
            ;;
        firewalld)
            firewall-cmd --permanent --add-port=$DASHBOARD_PORT/tcp
            firewall-cmd --permanent --add-port=$AGENT_PORT/tcp
            firewall-cmd --permanent --add-port=$ENROLLMENT_PORT/tcp
            firewall-cmd --permanent --add-port=$API_PORT/tcp
            firewall-cmd --permanent --add-port=$INDEXER_PORT/tcp
            firewall-cmd --reload
            ;;
        iptables)
            iptables -A INPUT -p tcp --dport $DASHBOARD_PORT -j ACCEPT
            iptables -A INPUT -p tcp --dport $AGENT_PORT -j ACCEPT
            iptables -A INPUT -p tcp --dport $ENROLLMENT_PORT -j ACCEPT
            iptables -A INPUT -p tcp --dport $API_PORT -j ACCEPT
            iptables -A INPUT -p tcp --dport $INDEXER_PORT -j ACCEPT
            ;;
    esac

    success "Firewall configured for Wazuh ports"
}

#=============================================================================
# CHECK STATUS
#=============================================================================
check_status() {
    header "Wazuh Server Status"

    echo "=== Wazuh Indexer ==="
    systemctl status wazuh-indexer --no-pager 2>/dev/null || echo "Not installed"
    echo ""

    echo "=== Wazuh Manager ==="
    systemctl status wazuh-manager --no-pager 2>/dev/null || echo "Not installed"
    echo ""

    echo "=== Filebeat ==="
    systemctl status filebeat --no-pager 2>/dev/null || echo "Not installed"
    echo ""

    echo "=== Wazuh Dashboard ==="
    systemctl status wazuh-dashboard --no-pager 2>/dev/null || echo "Not installed"
    echo ""

    info "Ports:"
    echo "  Dashboard: https://$WAZUH_MANAGER_IP:$DASHBOARD_PORT"
    echo "  API: https://$WAZUH_MANAGER_IP:$API_PORT"
    echo "  Agent Events: $WAZUH_MANAGER_IP:$AGENT_PORT"
    echo "  Agent Enrollment: $WAZUH_MANAGER_IP:$ENROLLMENT_PORT"

    echo ""
    info "Connected Agents:"
    $WAZUH_DIR/bin/agent_control -l 2>/dev/null || echo "Manager not running"
}

#=============================================================================
# QUICK SETUP (DOCKER)
#=============================================================================
quick_setup_docker() {
    header "Quick Setup - Docker Compose"

    if ! command -v docker &>/dev/null; then
        error "Docker not installed. Install Docker first:"
        echo "  curl -fsSL https://get.docker.com | sh"
        echo "  systemctl enable --now docker"
        return 1
    fi

    if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null; then
        error "Docker Compose not installed"
        return 1
    fi

    # Check if Docker daemon is running
    if ! docker info &>/dev/null; then
        warn "Docker daemon is not running. Attempting to start..."
        if systemctl is-active --quiet docker; then
            error "Docker service is active but daemon is not responding"
            error "Check Docker logs: journalctl -u docker"
            return 1
        else
            info "Starting Docker service..."
            systemctl start docker
            systemctl enable docker
            
            # Wait for Docker to be ready
            local retries=0
            while ! docker info &>/dev/null && [ $retries -lt 10 ]; do
                sleep 1
                retries=$((retries + 1))
            done
            
            if ! docker info &>/dev/null; then
                error "Failed to start Docker daemon"
                error "Try manually: systemctl start docker"
                return 1
            fi
            success "Docker daemon started"
        fi
    fi

    # Verify Docker socket permissions
    if [ ! -S /var/run/docker.sock ]; then
        error "Docker socket not found at /var/run/docker.sock"
        return 1
    fi

    local wazuh_dir="/opt/wazuh-docker"
    mkdir -p "$wazuh_dir"
    cd "$wazuh_dir"

    # Download official docker-compose
    info "Downloading Wazuh Docker Compose configuration..."
    curl -sO https://raw.githubusercontent.com/wazuh/wazuh-docker/v$WAZUH_VERSION/single-node/docker-compose.yml

    # Generate certificates
    info "Downloading certificate generation script..."
    curl -sO https://raw.githubusercontent.com/wazuh/wazuh-docker/v$WAZUH_VERSION/single-node/generate-indexer-certs.yml
    
    info "Generating SSL certificates..."
    if docker compose -f generate-indexer-certs.yml run --rm generator 2>/dev/null; then
        success "Certificates generated"
    elif docker-compose -f generate-indexer-certs.yml run --rm generator 2>/dev/null; then
        success "Certificates generated"
    else
        error "Failed to generate certificates"
        error "Check Docker daemon: systemctl status docker"
        return 1
    fi

    # Start Wazuh
    info "Starting Wazuh containers..."
    if docker compose up -d 2>/dev/null; then
        success "Containers started"
    elif docker-compose up -d 2>/dev/null; then
        success "Containers started"
    else
        error "Failed to start containers"
        error "Check Docker daemon: systemctl status docker"
        error "Check Docker logs: journalctl -u docker"
        return 1
    fi

    # Wait for startup
    info "Waiting for services to start (this may take 2-3 minutes)..."
    sleep 120

    success "============================================"
    success "Wazuh Docker Setup Complete!"
    success "============================================"
    echo ""
    info "Dashboard: https://$WAZUH_MANAGER_IP:443"
    info "Username: admin"
    info "Password: SecretPassword"
    echo ""
    warn "Change the default password immediately!"
    echo ""
    info "To stop: cd $wazuh_dir && docker compose down"
    info "To view logs: docker compose logs -f"

    log_action "Installed Wazuh Server via Docker"
}

#=============================================================================
# FULL INSTALLATION
#=============================================================================
full_install() {
    header "Full Installation - Package-based"

    check_requirements
    generate_passwords
    add_wazuh_repo
    install_indexer
    install_manager
    install_filebeat
    install_dashboard
    configure_firewall

    # Clean up
    rm -rf /tmp/wazuh-certs

    echo ""
    success "============================================"
    success "Wazuh Server Setup Complete!"
    success "============================================"
    echo ""
    warn "SAVE THESE CREDENTIALS!"
    cat /root/.wazuh/credentials.txt
    echo ""
    info "Dashboard URL: https://$WAZUH_MANAGER_IP:$DASHBOARD_PORT"
    info "Use the admin credentials above to log in"
    echo ""
    info "To configure agents, use:"
    echo "  WAZUH_MANAGER=\"$WAZUH_MANAGER_IP\""
    echo ""

    log_action "Installed Wazuh Server (all-in-one)"
}

#=============================================================================
# MAIN MENU
#=============================================================================
main() {
    # Auto-detect IP
    WAZUH_MANAGER_IP=$(hostname -I | awk '{print $1}')

    echo ""
    echo "Wazuh Server Options:"
    echo "1) Quick setup - Docker Compose (recommended for testing)"
    echo "2) Full installation - Package-based (recommended for production)"
    echo "3) Check status"
    echo "4) View credentials"
    echo "5) Restart all services"
    echo "6) Stop all services"
    echo "7) View agent list"
    echo ""
    read -p "Select option [1-7]: " choice

    case $choice in
        1) quick_setup_docker ;;
        2) full_install ;;
        3) check_status ;;
        4)
            if [ -f /root/.wazuh/credentials.txt ]; then
                cat /root/.wazuh/credentials.txt
            else
                error "Credentials file not found"
                info "Default Docker credentials: admin / SecretPassword"
            fi
            ;;
        5)
            systemctl restart wazuh-indexer wazuh-manager filebeat wazuh-dashboard
            success "Services restarted"
            ;;
        6)
            systemctl stop wazuh-dashboard filebeat wazuh-manager wazuh-indexer
            success "Services stopped"
            ;;
        7)
            $WAZUH_DIR/bin/agent_control -l 2>/dev/null || error "Manager not running"
            ;;
        *) error "Invalid option" ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
