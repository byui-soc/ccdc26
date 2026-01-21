# CCDC26 Wazuh Content

Wazuh is a free, open-source security monitoring platform that provides unified XDR and SIEM protection. This directory contains custom content for CCDC competitions.

## Key Features

- **Free & Open Source** - No data limits, GPLv2 license
- **File Integrity Monitoring** - Real-time file change detection
- **Vulnerability Detection** - CVE scanning for installed packages
- **Active Response** - Auto-block brute force attacks
- **CIS Benchmarks** - Built-in compliance checking
- **Lightweight Agents** - ~50MB footprint

## Directory Structure

```
wazuh-content/
├── rules/
│   └── ccdc-custom-rules.xml      # Custom detection rules for CCDC
├── decoders/
│   └── (custom log decoders)
├── cdb-lists/
│   └── (threat intelligence lists)
├── docker/
│   ├── docker-compose.yml         # Quick server deployment
│   ├── generate-certs.yml         # Certificate generation
│   └── config/                    # Docker configuration files
└── README.md
```

## Quick Start

### Option 1: Docker Deployment (Recommended for Testing)

```bash
cd docker/

# Generate SSL certificates
docker compose -f generate-certs.yml run --rm generator

# Start Wazuh (manager + indexer + dashboard)
docker compose up -d

# Wait 2-3 minutes for services to start
# Access dashboard: https://localhost:443
# Username: admin
# Password: SecretPassword
```

### Option 2: Package Installation (Recommended for Production)

```bash
# On the Wazuh server
cd ../linux-scripts/tools/
sudo ./wazuh-server.sh
# Select option 2 for full package-based installation
```

## Deploying Agents

### Linux Agent

```bash
# Edit the script to set your manager IP
sudo nano ../linux-scripts/tools/wazuh-agent.sh
# Set: WAZUH_MANAGER="your-manager-ip"

# Run installation
sudo ./wazuh-agent.sh
# Select option 1 for quick setup
```

### Windows Agent

```powershell
# Edit the script to set your manager IP
# Set: $WAZUH_MANAGER = "your-manager-ip"

# Run installation (as Administrator)
.\Install-WazuhAgent.ps1
# Select option 1 for quick setup
```

### Ansible Deployment

```bash
# Deploy to all hosts in inventory
ansible-playbook -i inventory.ini deploy_wazuh.yml -e "wazuh_manager=10.0.0.100"

# With registration password
ansible-playbook -i inventory.ini deploy_wazuh.yml \
  -e "wazuh_manager=10.0.0.100" \
  -e "wazuh_registration_password=MySecretPassword"
```

## Custom Rules

### Installation

Copy rules to the Wazuh manager:

```bash
# Package installation
sudo cp rules/ccdc-custom-rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager

# Docker installation (rules are auto-mounted via volume)
docker compose restart wazuh.manager
```

### Rule Categories

The custom rules (IDs 100000-100999) cover:

| Category | Rule IDs | Description |
|----------|----------|-------------|
| Authentication | 100001-100006 | Brute force, admin logins, after-hours access |
| User/Account | 100010-100015 | User creation, privilege escalation, sudoers |
| Persistence | 100020-100025 | Cron jobs, systemd services, scheduled tasks |
| Network | 100030-100039 | Reverse shell ports, suspicious connections |
| Process/Execution | 100040-100046 | Suspicious processes, PowerShell, SUID binaries |
| Web Attacks | 100050-100052 | Web shells, SQL injection, directory traversal |
| Database | 100060-100069 | Database authentication failures |
| Mail | 100070-100079 | Mail server authentication |
| System | 100080-100082 | Kernel modules, firewall changes, log clearing |
| Fail2Ban | 100090-100099 | IP bans |

### Example Rule

```xml
<!-- Brute Force Detection - 5+ failures in 5 minutes -->
<rule id="100001" level="10" frequency="5" timeframe="300">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip/>
  <description>CCDC: Brute force attack (5+ failed SSH logins)</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>authentication_failures,brute_force,</group>
</rule>
```

## Wazuh Features for CCDC

### File Integrity Monitoring (FIM)

Automatically monitors critical directories:
- `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`
- `/var/www` (web roots)
- Critical files: `passwd`, `shadow`, `sudoers`, `sshd_config`

### Rootkit Detection

Runs every 12 hours to detect:
- Known rootkit files and trojans
- Hidden processes and ports
- Suspicious device files

### System Inventory

Collects every hour:
- Installed packages
- Running processes
- Open ports
- OS information

### Vulnerability Detection

Automatically scans for:
- CVEs affecting installed packages
- Missing security patches

### Active Response

Auto-blocks brute force attacks:
- Firewall-drop: Blocks attacker IP
- Configurable thresholds and duration

## Dashboard Access

| Component | URL | Default Credentials |
|-----------|-----|---------------------|
| Wazuh Dashboard | https://server:443 | admin / SecretPassword |
| Wazuh API | https://server:55000 | wazuh-wui / MyS3cr37P450r.*- |

### Key Dashboards

1. **Security Events** - Real-time alert feed
2. **Integrity Monitoring** - File changes across all agents
3. **Vulnerabilities** - CVE dashboard for all systems
4. **Agents** - Agent status and inventory
5. **MITRE ATT&CK** - Alerts mapped to MITRE techniques

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 443 | TCP | Wazuh Dashboard (HTTPS) |
| 1514 | TCP | Agent events |
| 1515 | TCP | Agent enrollment |
| 9200 | TCP | Wazuh Indexer API |
| 55000 | TCP | Wazuh API |

## Troubleshooting

### Agent Not Connecting

```bash
# Check agent status
sudo /var/ossec/bin/wazuh-control status

# View logs
sudo tail -f /var/ossec/logs/ossec.log

# Test connectivity
nc -zv <manager-ip> 1514
```

### Dashboard Not Loading

```bash
# Check service status
sudo systemctl status wazuh-dashboard

# Check logs
sudo tail -f /var/log/wazuh-dashboard/dashboard.log
```

### High Memory Usage

Adjust JVM heap size in `/etc/wazuh-indexer/jvm.options`:
```
-Xms1g
-Xmx1g
```

## Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh GitHub](https://github.com/wazuh/wazuh)
- [Rule Syntax Reference](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [MITRE ATT&CK Mapping](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)
