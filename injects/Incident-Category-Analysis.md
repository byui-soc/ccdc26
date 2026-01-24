# Incident Analysis by Attack Category

**TO:** Management  
**FROM:** Security Team  
**DATE:** January 24, 2026  
**RE:** Analysis of Competition Incidents and Mitigation Priorities

---

## Incident Catalog by Category

### A. Reconnaissance / Intelligence

No direct evidence of reconnaissance observed, though the attacker clearly had knowledge of our network topology and default credentials. The malware's config file contained specific IP addresses of our systems, suggesting prior intelligence gathering.

### B. Initial Access

**Incident: Splunk Server Compromise**
- Attacker accessed Splunk server using unchanged default password
- Access originated from Ubuntu workstation (compromised first)
- Default credentials were not changed during initial hardening

**Incident: SSH Malware Propagation**
- Malware used credentials stored in /etc/config.txt to SSH into systems
- Targeted specific hosts: 172.20.242.102, 172.20.242.254 (Palo Alto)

### C. Execution

**Incident: SSH Malware**
- Python script (/etc/startup_check.py) executed via systemd service
- Used Paramiko library for SSH operations
- Installer script (/usr/share/startup_check-installer.sh) executed on target systems to install dependencies

### D. Persistence

**Incident: SSH Malware**
- Systemd service (startup_check.service) for automatic startup
- Script reinstalled itself on target systems
- 10-minute sleep loop to maintain continuous operation
- Persistence survived reboots until manually removed

### E. Privilege Escalation

No observed privilege escalation. Malware ran as root from initial compromise. Splunk access used existing admin credentials.

### F. Lateral Movement

**Incident: SSH Malware Propagation**
- Automated SSH connections to spread across Linux systems
- Used Paramiko library to connect and execute installer script
- Targeted systems listed in config file
- Successfully spread to: Ecom, Webmail, Splunk servers

**Incident: Splunk Compromise**
- Attacker pivoted from Ubuntu workstation to Splunk server
- Used network access and known credentials to move laterally

### G. Command & Control (C2)

**Incident: SSH Malware Beaconing**
- 10-minute beacon interval (time.sleep(600))
- Outbound SSH connections to target systems
- Logged activity: "Startup Files Checked - Do Not Restart"
- Packet captures showed SSH-2.0-paramiko_2.12.0 banner

### H. Collection & Exfiltration

No confirmed data exfiltration. The malware's primary function was propagation rather than data theft. Splunk logs were destroyed rather than exfiltrated.

### I. Impact / Objective

**Incident: Splunk Service Destruction**
- Attacker wiped Splunk binary and service
- Resulted in loss of centralized logging capability
- Required service restoration

[SCREENSHOT PLACEHOLDER: Splunk logs showing attacker activity]

### J. Evasion & Anti-Detection

**Incident: SSH Malware**
- Generic process name (startup_check.py) designed to look legitimate
- Log message "Startup Files Checked - Do Not Restart" intended to appear routine
- Installed in system directories (/etc, /usr/share) to blend in

**Incident: Splunk Destruction**
- Destroying logging infrastructure eliminated evidence trail
- Attacker targeted our detection capability directly

---

## Priority Categories for Mitigation

After reviewing all incidents, we're focusing mitigation efforts on two categories:

### Priority 1: Initial Access

**Why this category:**
- Both major incidents stemmed from credential problems
- Unchanged default password on Splunk allowed direct compromise
- Hardcoded credentials in malware config enabled automated propagation
- This is the root cause—if we block initial access, the rest of the attack chain doesn't happen

**Mitigation Plan:**

1. **Immediate password audit** - Every system, every service, no exceptions. If it has a default password, it gets changed now.

2. **Password management process** - Documented procedure for initial deployment that includes mandatory credential changes before going live.

3. **Credential inventory** - Maintain list of all service accounts, their purposes, and last rotation date.

4. **Automated credential scanning** - Run tools to detect default/weak credentials before attackers do.

5. **SSH key-based authentication** - Disable password auth for SSH where possible. Keys can't be guessed.

6. **Network segmentation** - Even with valid credentials, limit what systems can talk to each other. The Ubuntu workstation shouldn't have direct Splunk admin access.

### Priority 2: Lateral Movement

**Why this category:**
- Once attackers got in, they moved freely across our network
- Malware spread to multiple Linux servers automatically
- Attacker pivoted from workstation to critical infrastructure
- Stopping lateral movement contains the blast radius of any breach

**Mitigation Plan:**

1. **Host-based firewalls** - Restrict which systems can initiate connections to which. Workstations shouldn't SSH to servers.

2. **Outbound connection monitoring** - Our detect-outbound-ssh.sh script catches this. Deploy network-wide.

3. **Network segmentation** - Separate workstations from servers. Separate production from management.

4. **Service account restrictions** - Service accounts only need access to specific systems. Don't use one account everywhere.

5. **Jump host architecture** - Administrative access goes through a hardened jump host with logging, not direct connections.

6. **Coordinated response capability** - When we find malware spreading, we need to clean all systems simultaneously. We learned this the hard way.

---

## AI and Data Analytics Opportunities

The following categories would benefit most from AI-based detection and analytics:

### C2 Detection (Command & Control)

AI/ML is well-suited for detecting beaconing patterns:
- Identifying regular interval communications (like our 10-minute beacon)
- Detecting anomalous outbound connections
- Recognizing C2 traffic patterns even when encrypted
- Baseline normal network behavior and alert on deviations

Tools like Splunk's ML Toolkit or dedicated NDR solutions can learn what "normal" looks like and flag statistical outliers.

### Lateral Movement Detection

AI can identify unusual access patterns:
- User accounts accessing systems they don't normally touch
- Service accounts behaving differently than their baseline
- Authentication patterns that indicate credential theft
- Graph analysis of access relationships to spot anomalies

### Evasion & Anti-Detection

AI can catch what signature-based tools miss:
- Behavioral analysis of processes regardless of name
- Detecting "living off the land" techniques
- Identifying processes that look legitimate but behave suspiciously
- Correlating weak signals across multiple data sources

### Reconnaissance Detection

AI can spot subtle scanning and enumeration:
- Low-and-slow port scans that evade threshold alerts
- DNS query patterns indicating reconnaissance
- LDAP enumeration attempts
- Unusual access to directory services

---

## Summary

Our two biggest gaps were **unchanged default credentials** and **unrestricted lateral movement**. Fix those and we dramatically reduce our attack surface. The Splunk compromise in particular was entirely preventable—a default password on critical infrastructure is an unforced error.

Going forward, AI-based detection makes the most sense for C2 and lateral movement, where pattern recognition and behavioral analysis can catch what static rules miss.

[ADDITIONAL EVIDENCE PENDING - Screenshots of Splunk compromise logs to be added]
