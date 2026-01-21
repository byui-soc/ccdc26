#!/bin/bash
# CCDC26 Linux Toolkit - Wazuh Agent Setup
# Deploys and configures Wazuh agent to forward logs to central Wazuh manager

source "$(dirname "$0")/../utils/common.sh"
require_root

header "Wazuh Agent Setup"

#=============================================================================
# CONFIGURATION - UPDATE THESE VALUES FOR YOUR ENVIRONMENT
#=============================================================================
# CCDC NOTE: Ubuntu Workstation gets DHCP! Check its IP after drop flag.
# For competition, this should be the Ubuntu Workstation's IP where Wazuh server runs.
WAZUH_MANAGER="${WAZUH_MANAGER:-CHANGE_ME}"  # Can also set via environment variable
WAZUH_REGISTRATION_PASSWORD=""       # Optional: registration password (leave empty for no auth)
WAZUH_AGENT_GROUP="default"          # Agent group for configuration
WAZUH_VERSION="4.7.2"                # Wazuh version

# Auto-detect if we're in competition environment (172.20.x.x range)
if [ "$WAZUH_MANAGER" = "CHANGE_ME" ]; then
    # Try to find Wazuh manager on common competition IPs
    for ip in 172.20.242.{1..50}; do
        if nc -zw1 "$ip" 1514 2>/dev/null; then
            info "Auto-detected Wazuh manager at $ip"
            WAZUH_MANAGER="$ip"
            break
        fi
    done 2>/dev/null
fi

# Paths
WAZUH_DIR="/var/ossec"
WAZUH_CONF="$WAZUH_DIR/etc/ossec.conf"

#=============================================================================
# VALIDATION
#=============================================================================
validate_config() {
    if [ "$WAZUH_MANAGER" = "CHANGE_ME" ]; then
        error "WAZUH_MANAGER is not configured!"
        error "Edit this script and set WAZUH_MANAGER to your Wazuh manager IP/hostname"
        info "Example: WAZUH_MANAGER=\"192.168.1.100\" or WAZUH_MANAGER=\"wazuh.local\""
        exit 1
    fi
}

#=============================================================================
# ADD WAZUH REPOSITORY
#=============================================================================
add_wazuh_repo() {
    header "Adding Wazuh Repository"

    case "$DISTRO_FAMILY" in
        debian)
            # Install prerequisites
            apt-get update
            apt-get install -y curl apt-transport-https gnupg2

            # Add GPG key
            curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

            # Add repository
            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list

            apt-get update
            success "Wazuh repository added (Debian/Ubuntu)"
            ;;

        rhel)
            # Import GPG key
            rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

            # Add repository
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

        suse)
            # Import GPG key
            rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

            # Add repository
            cat > /etc/zypp/repos.d/wazuh.repo << 'EOF'
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
EOF

            zypper refresh
            success "Wazuh repository added (openSUSE/SLES)"
            ;;

        alpine)
            warn "Alpine Linux requires manual installation"
            info "Download from: https://packages.wazuh.com/4.x/alpine/"
            return 1
            ;;

        arch)
            warn "Arch Linux - using AUR or manual installation"
            info "Install from AUR: yay -S wazuh-agent"
            return 1
            ;;

        *)
            error "Unsupported distribution: $DISTRO_FAMILY"
            return 1
            ;;
    esac
}

#=============================================================================
# INSTALL WAZUH AGENT
#=============================================================================
install_wazuh_agent() {
    header "Installing Wazuh Agent"

    if [ -d "$WAZUH_DIR" ] && [ -f "$WAZUH_DIR/bin/wazuh-control" ]; then
        info "Wazuh Agent already installed at $WAZUH_DIR"
        return 0
    fi

    case "$DISTRO_FAMILY" in
        debian)
            WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent
            ;;
        rhel)
            WAZUH_MANAGER="$WAZUH_MANAGER" $PKG_MGR install -y wazuh-agent
            ;;
        suse)
            WAZUH_MANAGER="$WAZUH_MANAGER" zypper install -y wazuh-agent
            ;;
        *)
            error "Cannot install on $DISTRO_FAMILY"
            return 1
            ;;
    esac

    if [ -d "$WAZUH_DIR" ]; then
        success "Wazuh Agent installed"
    else
        error "Wazuh Agent installation failed"
        return 1
    fi
}

#=============================================================================
# CONFIGURE WAZUH AGENT
#=============================================================================
configure_agent() {
    header "Configuring Wazuh Agent"

    backup_file "$WAZUH_CONF"

    # Update manager address in config
    if [ -f "$WAZUH_CONF" ]; then
        # Replace the manager address
        sed -i "s/<address>.*<\/address>/<address>$WAZUH_MANAGER<\/address>/g" "$WAZUH_CONF"
        success "Manager address set to: $WAZUH_MANAGER"
    fi

    # Create custom ossec.conf with enhanced monitoring
    cat > "$WAZUH_DIR/etc/ossec.conf" << EOF
<!--
  CCDC26 Wazuh Agent Configuration
  Generated: $(date)
  Manager: $WAZUH_MANAGER
-->

<ossec_config>
  <client>
    <server>
      <address>$WAZUH_MANAGER</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>$DISTRO_FAMILY</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Log Collection -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <!-- Web Server Logs -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/access_log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/error_log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>

  <!-- Database Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mysql/error.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/postgresql/*.log</location>
  </localfile>

  <!-- Mail Server Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mail.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/maillog</location>
  </localfile>

  <!-- DNS Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/named/*.log</location>
  </localfile>

  <!-- FTP Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/vsftpd.log</location>
  </localfile>

  <!-- Fail2Ban Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>

  <!-- CCDC Toolkit Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/ccdc-toolkit/*.log</location>
  </localfile>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>

    <!-- Critical directories -->
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/usr/bin</directories>
    <directories check_all="yes" realtime="yes">/usr/sbin</directories>
    <directories check_all="yes" realtime="yes">/bin</directories>
    <directories check_all="yes" realtime="yes">/sbin</directories>
    <directories check_all="yes">/boot</directories>

    <!-- Web roots -->
    <directories check_all="yes" realtime="yes">/var/www</directories>

    <!-- Critical files -->
    <directories check_all="yes" realtime="yes">/etc/passwd</directories>
    <directories check_all="yes" realtime="yes">/etc/shadow</directories>
    <directories check_all="yes" realtime="yes">/etc/group</directories>
    <directories check_all="yes" realtime="yes">/etc/sudoers</directories>
    <directories check_all="yes" realtime="yes">/etc/ssh/sshd_config</directories>
    <directories check_all="yes" realtime="yes">/etc/crontab</directories>
    <directories check_all="yes" realtime="yes">/etc/cron.d</directories>

    <!-- Ignore patterns -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/resolv.conf</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
  </syscheck>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>$WAZUH_DIR/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>$WAZUH_DIR/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
  </rootcheck>

  <!-- System Inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <packages>yes</packages>
    <os>yes</os>
    <hotfixes>yes</hotfixes>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <!-- Vulnerability Detection -->
  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
  </wodle>

  <!-- Active Response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>$WAZUH_DIR/etc/wpk_root.pem</ca_store>
  </active-response>

  <!-- Logging -->
  <logging>
    <log_format>json</log_format>
  </logging>

</ossec_config>
EOF

    chown root:wazuh "$WAZUH_CONF"
    chmod 640 "$WAZUH_CONF"

    success "Agent configuration created"
}

#=============================================================================
# REGISTER AGENT WITH MANAGER
#=============================================================================
register_agent() {
    header "Registering Agent with Manager"

    local hostname=$(hostname)

    # Check if already registered
    if [ -f "$WAZUH_DIR/etc/client.keys" ] && [ -s "$WAZUH_DIR/etc/client.keys" ]; then
        info "Agent already registered"
        cat "$WAZUH_DIR/etc/client.keys"
        return 0
    fi

    # Try auto-enrollment first (agent-auth)
    if [ -f "$WAZUH_DIR/bin/agent-auth" ]; then
        info "Attempting auto-enrollment with manager..."

        local auth_args="-m $WAZUH_MANAGER -A $hostname"

        # Add password if configured
        if [ -n "$WAZUH_REGISTRATION_PASSWORD" ]; then
            auth_args="$auth_args -P $WAZUH_REGISTRATION_PASSWORD"
        fi

        # Add group if configured
        if [ -n "$WAZUH_AGENT_GROUP" ] && [ "$WAZUH_AGENT_GROUP" != "default" ]; then
            auth_args="$auth_args -G $WAZUH_AGENT_GROUP"
        fi

        if $WAZUH_DIR/bin/agent-auth $auth_args 2>/dev/null; then
            success "Agent registered successfully"
            cat "$WAZUH_DIR/etc/client.keys"
            return 0
        else
            warn "Auto-enrollment failed. Manual registration may be required."
            info "On the Wazuh manager, run:"
            echo "  /var/ossec/bin/manage_agents"
            info "Then import the key on this agent with:"
            echo "  /var/ossec/bin/manage_agents -i <KEY>"
            return 1
        fi
    else
        error "agent-auth not found. Please register manually."
        return 1
    fi
}

#=============================================================================
# START WAZUH AGENT
#=============================================================================
start_agent() {
    header "Starting Wazuh Agent"

    # Disable automatic repository updates to prevent agent changes
    case "$DISTRO_FAMILY" in
        debian)
            echo "wazuh-agent hold" | dpkg --set-selections 2>/dev/null
            ;;
        rhel)
            if [ -f /etc/yum.repos.d/wazuh.repo ]; then
                sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/wazuh.repo
            fi
            ;;
    esac

    # Enable and start service
    case "$INIT_SYSTEM" in
        systemd)
            systemctl daemon-reload
            systemctl enable wazuh-agent
            systemctl start wazuh-agent

            sleep 3
            if systemctl is-active --quiet wazuh-agent; then
                success "Wazuh Agent is running"
                systemctl status wazuh-agent --no-pager
            else
                error "Wazuh Agent failed to start"
                systemctl status wazuh-agent --no-pager
                return 1
            fi
            ;;
        *)
            $WAZUH_DIR/bin/wazuh-control start
            sleep 3
            if $WAZUH_DIR/bin/wazuh-control status | grep -q "running"; then
                success "Wazuh Agent is running"
            else
                error "Wazuh Agent failed to start"
                return 1
            fi
            ;;
    esac
}

#=============================================================================
# CHECK STATUS
#=============================================================================
check_status() {
    header "Wazuh Agent Status"

    if [ ! -d "$WAZUH_DIR" ]; then
        error "Wazuh Agent not installed"
        return 1
    fi

    # Service status
    case "$INIT_SYSTEM" in
        systemd)
            systemctl status wazuh-agent --no-pager
            ;;
        *)
            $WAZUH_DIR/bin/wazuh-control status
            ;;
    esac

    echo ""
    info "Manager: $WAZUH_MANAGER"

    echo ""
    info "Agent Info:"
    $WAZUH_DIR/bin/wazuh-control info 2>/dev/null || cat "$WAZUH_DIR/etc/client.keys" 2>/dev/null

    echo ""
    info "Connection Status:"
    grep -E "(Connected|Disconnected|ERROR)" "$WAZUH_DIR/logs/ossec.log" 2>/dev/null | tail -5
}

#=============================================================================
# TEST CONNECTIVITY
#=============================================================================
test_connectivity() {
    header "Testing Wazuh Manager Connectivity"

    validate_config

    info "Testing connection to $WAZUH_MANAGER:1514..."

    if command -v nc &>/dev/null; then
        if nc -zv "$WAZUH_MANAGER" 1514 2>&1 | grep -q "succeeded\|open"; then
            success "Connection to $WAZUH_MANAGER:1514 successful"
        else
            error "Cannot connect to $WAZUH_MANAGER:1514"
            warn "Ensure the Wazuh manager is running and port 1514 is open"
        fi
    elif command -v timeout &>/dev/null; then
        if timeout 5 bash -c "echo > /dev/tcp/$WAZUH_MANAGER/1514" 2>/dev/null; then
            success "Connection to $WAZUH_MANAGER:1514 successful"
        else
            error "Cannot connect to $WAZUH_MANAGER:1514"
        fi
    else
        warn "Cannot test connectivity (nc/timeout not available)"
    fi

    # Also test enrollment port
    info "Testing enrollment port $WAZUH_MANAGER:1515..."
    if command -v nc &>/dev/null; then
        if nc -zv "$WAZUH_MANAGER" 1515 2>&1 | grep -q "succeeded\|open"; then
            success "Enrollment port 1515 is open"
        else
            warn "Enrollment port 1515 not accessible (may need manual registration)"
        fi
    fi
}

#=============================================================================
# UNINSTALL
#=============================================================================
uninstall_agent() {
    header "Uninstalling Wazuh Agent"

    read -p "Are you sure you want to uninstall? [y/N] " confirm
    [[ "$confirm" != [yY] ]] && return

    # Stop service
    case "$INIT_SYSTEM" in
        systemd)
            systemctl stop wazuh-agent
            systemctl disable wazuh-agent
            ;;
        *)
            $WAZUH_DIR/bin/wazuh-control stop
            ;;
    esac

    # Remove package
    case "$DISTRO_FAMILY" in
        debian)
            apt-get remove -y wazuh-agent
            apt-get purge -y wazuh-agent
            ;;
        rhel)
            $PKG_MGR remove -y wazuh-agent
            ;;
        suse)
            zypper remove -y wazuh-agent
            ;;
    esac

    # Remove directories
    rm -rf "$WAZUH_DIR"

    success "Wazuh Agent uninstalled"
}

#=============================================================================
# QUICK SETUP (FULL INSTALLATION)
#=============================================================================
quick_setup() {
    header "Quick Setup - Full Installation"

    validate_config
    add_wazuh_repo
    install_wazuh_agent
    configure_agent
    register_agent
    start_agent

    echo ""
    success "============================================"
    success "Wazuh Agent Setup Complete!"
    success "============================================"
    echo ""
    info "Manager: $WAZUH_MANAGER"
    info "Agent Config: $WAZUH_CONF"
    info "Logs: $WAZUH_DIR/logs/ossec.log"
    echo ""
    info "Features enabled:"
    echo "  - Log collection (auth, syslog, web, database, mail, DNS, FTP)"
    echo "  - File Integrity Monitoring (FIM)"
    echo "  - Rootkit detection"
    echo "  - System inventory"
    echo "  - Vulnerability detection"
    echo "  - Active response"
    echo ""
    warn "Verify the agent appears in Wazuh Dashboard under Agents"

    log_action "Installed Wazuh Agent -> $WAZUH_MANAGER"
}

#=============================================================================
# RECONFIGURE (UPDATE MANAGER)
#=============================================================================
reconfigure() {
    header "Reconfigure Wazuh Agent"

    echo "Current configuration:"
    grep -A2 "<server>" "$WAZUH_CONF" 2>/dev/null
    echo ""

    read -p "Enter new Wazuh manager IP/hostname (or press Enter to keep current): " new_manager
    [ -n "$new_manager" ] && WAZUH_MANAGER="$new_manager"

    configure_agent

    # Restart agent
    case "$INIT_SYSTEM" in
        systemd)
            systemctl restart wazuh-agent
            ;;
        *)
            $WAZUH_DIR/bin/wazuh-control restart
            ;;
    esac

    success "Reconfigured to connect to $WAZUH_MANAGER"
}

#=============================================================================
# MAIN MENU
#=============================================================================
main() {
    echo ""
    echo "Wazuh Agent Options:"
    echo "1) Quick setup (full installation)"
    echo "2) Check status"
    echo "3) Test manager connectivity"
    echo "4) Reconfigure manager address"
    echo "5) View recent logs"
    echo "6) Restart agent"
    echo "7) Stop agent"
    echo "8) Uninstall"
    echo ""
    read -p "Select option [1-8]: " choice

    case $choice in
        1) quick_setup ;;
        2) check_status ;;
        3) test_connectivity ;;
        4) reconfigure ;;
        5) tail -50 "$WAZUH_DIR/logs/ossec.log" 2>/dev/null ;;
        6)
            case "$INIT_SYSTEM" in
                systemd) systemctl restart wazuh-agent ;;
                *) $WAZUH_DIR/bin/wazuh-control restart ;;
            esac
            ;;
        7)
            case "$INIT_SYSTEM" in
                systemd) systemctl stop wazuh-agent ;;
                *) $WAZUH_DIR/bin/wazuh-control stop ;;
            esac
            ;;
        8) uninstall_agent ;;
        *) error "Invalid option" ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
