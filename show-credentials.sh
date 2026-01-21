#!/bin/bash
# CCDC26 - Quick Credentials Reference
# Run this to display all default credentials

cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════════════════╗
║              RMCCDC 2026 - TEAM 2 (BYU) - DEFAULT CREDENTIALS                 ║
║                      *** CHANGE THESE IMMEDIATELY! ***                        ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  NISE Accounts:   team02a - team02i                                           ║
║  Comp Accounts:   v2u1 - v2u8                                                 ║
║  Public IPs:      172.25.22.0/24                                              ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  LINUX SYSTEMS (172.20.242.0/24 - Behind Palo Alto)                          ║
║  ─────────────────────────────────────────────────────────────────────────    ║
║  Ubuntu Ecom     │ 172.20.242.30  │ sysadmin:changeme                        ║
║  Fedora Webmail  │ 172.20.242.40  │ sysadmin:changeme                        ║
║  Splunk Server   │ 172.20.242.20  │ root:changemenow                         ║
║                  │                │ sysadmin:changemenow                     ║
║                  │                │ admin:changeme (Splunk Web)              ║
║  Ubuntu Wks      │ DHCP (check!)  │ sysadmin:changeme    [Wazuh Server]      ║
║                                                                               ║
║  WINDOWS SYSTEMS (172.20.240.0/24 - Behind Cisco FTD)                        ║
║  ─────────────────────────────────────────────────────────────────────────    ║
║  AD/DNS 2019     │ 172.20.240.102 │ administrator:!Password123               ║
║  Web 2019        │ 172.20.240.101 │ administrator:!Password123               ║
║  FTP 2022        │ 172.20.240.104 │ administrator:!Password123               ║
║  Win11 Wks       │ 172.20.240.100 │ administrator:!Password123               ║
║                  │                │ UserOne:ChangeMe123                      ║
║                                                                               ║
║  NETWORK DEVICES                                                              ║
║  ─────────────────────────────────────────────────────────────────────────    ║
║  Palo Alto       │ 172.20.242.150 │ admin:Changeme123                        ║
║                  │ (from Ubuntu)  │                                          ║
║  Cisco FTD       │ 172.20.240.200 │ admin:!Changeme123                       ║
║                  │ (from Win11)   │                                          ║
║  VyOS Router     │ 172.16.101.1   │ vyos:changeme                            ║
║                                                                               ║
║  COMPETITION PORTALS                                                          ║
║  ─────────────────────────────────────────────────────────────────────────    ║
║  NISE Portal     │ ccdcadmin1.morainevalley.edu  │ team02a - team02i         ║
║  Competition     │ ccdc.cit.morainevalley.edu    │ v2u1 - v2u8               ║
║                                                                               ║
║  TEAM 2 PUBLIC IPs                                                            ║
║  ─────────────────────────────────────────────────────────────────────────    ║
║  Ubuntu Ecom     │ 172.25.22.11   │ Fedora Webmail │ 172.25.22.39            ║
║  Splunk          │ 172.25.22.9    │ AD/DNS         │ 172.25.22.155           ║
║  Web 2019        │ 172.25.22.140  │ FTP 2022       │ 172.25.22.162           ║
║  Win11 Wks       │ 172.25.22.144  │ Router Ext     │ 172.31.22.2             ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

QUICK PASSWORD CHANGE COMMANDS:
───────────────────────────────
# Change all via Ansible:
ansible-playbook -i ansible/inventory.ini ansible/change_all_passwords.yml -e "new_password=YourNewP@ss!"

# Linux manual:
passwd                           # Current user
sudo passwd root                 # Root user

# Windows PowerShell (as Admin):
net user administrator "NewP@ssw0rd!"

EOF
