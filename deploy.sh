#!/bin/bash
#=============================================================================
# CCDC26 All-in-One Deployment Script
#=============================================================================
# Master entry point for the CCDC26 toolkit
# Detects environment and provides appropriate options
#
# Usage:
#   ./deploy.sh              # Interactive menu
#   ./deploy.sh --quick      # Quick local harden
#   ./deploy.sh --ansible    # Ansible deployment menu
#=============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#=============================================================================
# COLORS
#=============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; }
header()  { echo -e "\n${BOLD}${PURPLE}=== $1 ===${NC}\n"; }

#=============================================================================
# ENVIRONMENT DETECTION
#=============================================================================
detect_environment() {
    # Check if we're on the target system or an Ansible controller
    IS_ANSIBLE_CONTROLLER=false
    IS_TARGET_SYSTEM=true
    
    # Check for Ansible (may be in user's ~/.local/bin from pip install)
    if command -v ansible &>/dev/null; then
        IS_ANSIBLE_CONTROLLER=true
    elif [ -f "$HOME/.local/bin/ansible" ]; then
        IS_ANSIBLE_CONTROLLER=true
        export PATH="$HOME/.local/bin:$PATH"
    elif [ -f "/home/$SUDO_USER/.local/bin/ansible" ] 2>/dev/null; then
        # Running as sudo, check the original user's pip install location
        IS_ANSIBLE_CONTROLLER=true
        export PATH="/home/$SUDO_USER/.local/bin:$PATH"
    elif python3 -c "import ansible" &>/dev/null; then
        IS_ANSIBLE_CONTROLLER=true
    fi
    
    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="$NAME"
        OS_ID="$ID"
    else
        OS_NAME="Unknown"
        OS_ID="unknown"
    fi
    
    # Check if root
    IS_ROOT=false
    if [ "$EUID" -eq 0 ]; then
        IS_ROOT=true
    fi
}

#=============================================================================
# BANNER
#=============================================================================
show_banner() {
    echo -e "${CYAN}"
    echo "  ██████╗ ██████╗██████╗  ██████╗██████╗  ██████╗ "
    echo " ██╔════╝██╔════╝██╔══██╗██╔════╝╚════██╗██╔════╝ "
    echo " ██║     ██║     ██║  ██║██║      █████╔╝███████╗ "
    echo " ██║     ██║     ██║  ██║██║     ██╔═══╝ ██╔═══██╗"
    echo " ╚██████╗╚██████╗██████╔╝╚██████╗███████╗╚██████╔╝"
    echo "  ╚═════╝ ╚═════╝╚═════╝  ╚═════╝╚══════╝ ╚═════╝ "
    echo -e "${NC}"
    echo -e "${BOLD}CCDC26 Defense Toolkit${NC}"
    echo ""
    echo -e "OS: ${GREEN}$OS_NAME${NC}"
    echo -e "Ansible: ${GREEN}$([ "$IS_ANSIBLE_CONTROLLER" = true ] && echo "Available" || echo "Not installed")${NC}"
    echo -e "Root: ${GREEN}$([ "$IS_ROOT" = true ] && echo "Yes" || echo "No")${NC}"
    echo ""
}

#=============================================================================
# LOCAL HARDENING MENU
#=============================================================================
local_menu() {
    header "Local Hardening Options"
    
    echo "1) Quick Harden (full-harden.sh with defaults)"
    echo "2) Interactive Harden (choose options)"
    echo "3) Service Hardening (harden-all.sh)"
    echo "4) Deploy Wazuh Agent (primary SIEM)"
    echo "5) Deploy Splunk Forwarder (backup SIEM)"
    echo "6) Hunt for Persistence"
    echo "7) Start Monitoring"
    echo "8) Incident Response Tools"
    echo "9) Deploy Wazuh Server (this system)"
    echo ""
    echo "0) Back to main menu"
    echo ""
    
    read -p "Select option: " choice
    
    case $choice in
        1)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Running Quick Harden"
            cd "$SCRIPT_DIR/linux-scripts"
            bash ./hardening/full-harden.sh
            ;;
        2)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Interactive Hardening"
            cd "$SCRIPT_DIR/linux-scripts/hardening"
            echo "Available hardening scripts:"
            echo "  1) users.sh     - User account hardening"
            echo "  2) ssh.sh       - SSH hardening"
            echo "  3) firewall.sh  - Firewall setup"
            echo "  4) services.sh  - Service management"
            echo "  5) permissions.sh - File permissions"
            echo "  6) kernel.sh    - Kernel hardening"
            echo ""
            read -p "Select script [1-6]: " script_choice
            case $script_choice in
                1) bash ./users.sh ;;
                2) bash ./ssh.sh ;;
                3) bash ./firewall.sh ;;
                4) bash ./services.sh ;;
                5) bash ./permissions.sh ;;
                6) bash ./kernel.sh ;;
                *) error "Invalid option" ;;
            esac
            ;;
        3)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Running Service Hardening"
            cd "$SCRIPT_DIR/linux-scripts/services"
            bash ./harden-all.sh
            ;;
        4)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Deploying Wazuh Agent (Primary SIEM)"
            read -p "Enter Wazuh manager IP: " wazuh_ip
            if [ -n "$wazuh_ip" ]; then
                sed -i "s/WAZUH_MANAGER=.*/WAZUH_MANAGER=\"$wazuh_ip\"/" "$SCRIPT_DIR/linux-scripts/tools/wazuh-agent.sh"
            fi
            cd "$SCRIPT_DIR/linux-scripts/tools"
            bash ./wazuh-agent.sh
            ;;
        5)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Deploying Splunk Forwarder (Backup SIEM)"
            info "Forwarding to competition Splunk server: 172.20.242.20:9997"
            cd "$SCRIPT_DIR/linux-scripts/tools"
            bash ./splunk-forwarder.sh
            ;;
        6)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Hunting for Persistence"
            cd "$SCRIPT_DIR/linux-scripts/persistence-hunting"
            bash ./full-hunt.sh
            ;;
        7)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Starting Monitoring"
            cd "$SCRIPT_DIR/linux-scripts/monitoring"
            bash ./deploy-monitoring.sh
            ;;
        8)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Incident Response Tools"
            cd "$SCRIPT_DIR/linux-scripts/incident-response"
            echo "Available IR scripts:"
            ls -1 *.sh
            echo ""
            read -p "Enter script name (or 'back'): " ir_script
            if [ "$ir_script" != "back" ] && [ -f "$ir_script" ]; then
                bash "./$ir_script"
            fi
            ;;
        9)
            if [ "$IS_ROOT" != true ]; then
                error "Must be root. Run: sudo $0"
                exit 1
            fi
            header "Deploying Wazuh Server"
            cd "$SCRIPT_DIR/linux-scripts/tools"
            bash ./wazuh-server.sh
            ;;
        0)
            return
            ;;
        *)
            error "Invalid option"
            ;;
    esac
}

#=============================================================================
# ANSIBLE MENU
#=============================================================================
ansible_menu() {
    if [ "$IS_ANSIBLE_CONTROLLER" != true ]; then
        error "Ansible is not installed"
        echo "Install with: pip3 install ansible pywinrm"
        return
    fi
    
    header "Ansible Deployment Options"
    
    echo "1) Generate inventory from CSV"
    echo "2) Test connectivity (ping all hosts)"
    echo "3) Password Reset + Create Users (changepw_kick.yml)"
    echo "4) Deploy Hardening Scripts"
    echo "5) Deploy Wazuh Agents (primary SIEM)"
    echo "6) Deploy Splunk Forwarders (backup SIEM)"
    echo "7) Gather Facts from All Hosts"
    echo "8) Run custom playbook"
    echo ""
    echo "0) Back to main menu"
    echo ""
    
    read -p "Select option: " choice
    
    ANSIBLE_DIR="$SCRIPT_DIR/ansible"
    
    case $choice in
        1)
            header "Generate Inventory from CSV"
            read -p "Enter path to CSV file: " csv_file
            if [ -f "$csv_file" ]; then
                python3 "$ANSIBLE_DIR/setup/csv2inv.py" "$csv_file" "$ANSIBLE_DIR/inventory.ini"
                success "Inventory generated: $ANSIBLE_DIR/inventory.ini"
            else
                error "File not found: $csv_file"
            fi
            ;;
        2)
            header "Testing Connectivity"
            ansible all -i "$ANSIBLE_DIR/inventory.ini" -m ping
            ;;
        3)
            header "Password Reset and User Creation"
            warn "This will reset ALL user passwords and create competition users!"
            read -p "Continue? (y/n): " confirm
            if [ "$confirm" = "y" ]; then
                ansible-playbook -i "$ANSIBLE_DIR/inventory.ini" "$ANSIBLE_DIR/changepw_kick.yml"
            fi
            ;;
        4)
            header "Deploy Hardening Scripts"
            echo "Options:"
            echo "  1) Deploy only (no execution)"
            echo "  2) Deploy and run full hardening"
            echo ""
            read -p "Select [1-2]: " deploy_opt
            
            case $deploy_opt in
                1)
                    ansible-playbook -i "$ANSIBLE_DIR/inventory.ini" "$ANSIBLE_DIR/deploy_hardening.yml"
                    ;;
                2)
                    ansible-playbook -i "$ANSIBLE_DIR/inventory.ini" "$ANSIBLE_DIR/deploy_hardening.yml" -e "run_full=true"
                    ;;
            esac
            ;;
        5)
            header "Deploy Wazuh Agents (Primary SIEM)"
            read -p "Enter Wazuh manager IP: " wazuh_ip
            if [ -n "$wazuh_ip" ]; then
                ansible-playbook -i "$ANSIBLE_DIR/inventory.ini" "$ANSIBLE_DIR/deploy_wazuh.yml" -e "wazuh_manager=$wazuh_ip"
            else
                error "Wazuh manager IP required"
            fi
            ;;
        6)
            header "Deploy Splunk Forwarders (Backup SIEM)"
            info "Forwarding to competition Splunk server: 172.20.242.20:9997"
            ansible-playbook -i "$ANSIBLE_DIR/inventory.ini" "$ANSIBLE_DIR/deploy_splunk_forwarders.yml"
            ;;
        7)
            header "Gathering Facts"
            ansible-playbook -i "$ANSIBLE_DIR/inventory.ini" "$ANSIBLE_DIR/gather_facts.yml"
            success "Facts saved to: $ANSIBLE_DIR/collected_facts/"
            ;;
        8)
            header "Run Custom Playbook"
            read -p "Enter playbook path: " playbook
            if [ -f "$playbook" ]; then
                ansible-playbook -i "$ANSIBLE_DIR/inventory.ini" "$playbook"
            else
                error "Playbook not found: $playbook"
            fi
            ;;
        0)
            return
            ;;
        *)
            error "Invalid option"
            ;;
    esac
}

#=============================================================================
# MAIN MENU
#=============================================================================
main_menu() {
    while true; do
        show_banner
        
        echo "Main Menu:"
        echo ""
        echo "1) Local Hardening (this system)"
        if [ "$IS_ANSIBLE_CONTROLLER" = true ]; then
            echo "2) Ansible Deployment (multiple systems)"
        else
            echo "2) Ansible Deployment (not available - install ansible)"
        fi
        echo "3) View Documentation"
        echo ""
        echo "q) Quit"
        echo ""
        
        read -p "Select option: " choice
        
        case $choice in
            1)
                local_menu
                ;;
            2)
                ansible_menu
                ;;
            3)
                header "Documentation"
                if command -v less &>/dev/null; then
                    less "$SCRIPT_DIR/README.md"
                else
                    cat "$SCRIPT_DIR/README.md"
                fi
                ;;
            q|Q)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                error "Invalid option"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        clear
    done
}

#=============================================================================
# COMMAND LINE OPTIONS
#=============================================================================
case "${1:-}" in
    --quick|-q)
        detect_environment
        if [ "$IS_ROOT" != true ]; then
            error "Must be root. Run: sudo $0 --quick"
            exit 1
        fi
        header "Quick Harden Mode"
        cd "$SCRIPT_DIR/linux-scripts"
        bash ./hardening/full-harden.sh
        exit 0
        ;;
    --ansible|-a)
        detect_environment
        ansible_menu
        exit 0
        ;;
    --help|-h)
        echo "CCDC26 Toolkit - All-in-One Deployment Script"
        echo ""
        echo "Usage: $0 [option]"
        echo ""
        echo "Options:"
        echo "  (none)      Interactive menu"
        echo "  --quick     Run quick hardening on local system"
        echo "  --ansible   Show Ansible deployment menu"
        echo "  --help      Show this help"
        echo ""
        exit 0
        ;;
esac

# Default: interactive menu
detect_environment
clear
main_menu
