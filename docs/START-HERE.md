# CCDC26 -- Competition Day Playbook

> This is the only doc you need at flag drop. Follow steps in order. No skipping.

---

## Step 0: Get the Toolkit (1 min)

### LINUX PERSON

```bash
git clone https://github.com/byui-soc/ccdc26.git /opt/ccdc26
cd /opt/ccdc26
sudo ./deploy.sh --configure     # Fill in IPs from competition packet
```

### WINDOWS PERSON (PowerShell as Admin)

```powershell
# Method 1: GitHub download
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://github.com/byui-soc/ccdc26/archive/refs/heads/main.zip" -OutFile C:\ccdc26.zip
Expand-Archive C:\ccdc26.zip -DestinationPath C:\; Rename-Item C:\ccdc26-main C:\ccdc26

# Method 2: From Linux controller (if no internet / GitHub blocked)
# Linux:  cd /opt/ccdc26 && python3 -m http.server 8080
Invoke-WebRequest -Uri "http://LINUX_IP:8080/ccdc26.zip" -OutFile C:\ccdc26.zip
Expand-Archive C:\ccdc26.zip -DestinationPath C:\; Rename-Item C:\ccdc26-main C:\ccdc26
```

---

## LINUX PERSON (Minutes 0-15)

```bash
cd /opt/ccdc26/monarch
python3 -m monarch repl
```

| Step | Command | What it does |
|------|---------|--------------|
| 1 | `scan SUBNET PASSWORD` | Discover all Linux hosts via SSH |
| 2 | `script 00-snapshot.sh` | Baseline users, crons, services, ports |
| 3 | `rotate` | Change ALL passwords + kick sessions |
| 4 | `script 01-harden.sh` | SSH lockdown, kernel hardening, permissions |
| 5 | `script 02-firewall.sh` | iptables/ufw on all hosts |
| 6 | `script 03-services.sh` | Harden running services (Apache, Postfix, DNS, etc.) |

---

## WINDOWS PERSON (Minutes 0-15, parallel)

```powershell
cd C:\ccdc26\dovetail\scripts
```

| Step | Command | What it does |
|------|---------|--------------|
| 1 | `.\00-snapshot.ps1` | Baseline users, services, tasks, ports |
| 2 | `.\01-blitz.ps1` | Harden this machine (CVE patches, Defender, services) |
| 3 | `.\02-ad.ps1` | Domain Controller hardening (Zerologon, noPac, Kerberos) |
| 4 | Repeat on each Windows machine | Or use Dovetail from DC to dispatch |

**Dovetail dispatch (from DC, after hardening all machines):**

```powershell
cd C:\ccdc26\dovetail
.\dovetail.ps1 -Connect -Targets "domain"              # Connect to all Windows hosts
.\dovetail.ps1 -Script .\scripts\01-blitz.ps1           # Harden all at once
```

---

## Verify Scored Services (Minutes 15-20)

| Service | Quick Test |
|---------|-----------|
| HTTP (Linux) | `curl -s http://<ecom-ip>` |
| HTTP (Windows/IIS) | Browse to `http://<web-win-ip>` |
| SMTP | `telnet <webmail-ip> 25` |
| POP3 | `telnet <webmail-ip> 110` |
| DNS | `nslookup <domain> <ad-ip>` |

- [ ] Check Stadium portal for green checks
- [ ] If a service is down: restart it, check logs, undo firewall rule if needed

---

## Firewalls (Minutes 20-30)

### Palo Alto (Linux zone)
- [ ] Browse to `https://<palo-alto-ip>` → Login → Allow scored service ports + ICMP → Change password

### Cisco FTD (Windows zone)
- [ ] Browse to `https://<cisco-ftd-ip>` → Login → Allow scored service ports + ICMP → Change password

### Router
- [ ] Login → Change password → Review ACLs

---

## After Stabilizing (Minutes 30-45)

### Linux (from Monarch REPL)

```
> script 04-splunk.sh           # Deploy Splunk forwarders to all hosts
> script 05-monitor.sh          # Deploy file/process/network monitors
```

### Windows (each machine, or via Dovetail)

```powershell
.\03-audit.ps1                  # Quick triage + audit
.\04-splunk.ps1                 # Install Splunk forwarder
.\05-monitor.ps1                # Start real-time monitoring
```

---

## Ongoing Threat Hunting

### Linux

```
> script hunt-persistence.sh    # Cron, services, users, binaries, startup
```

### Windows

```powershell
.\hunt-persistence.ps1          # Registry, tasks, WMI, services, COM, SSPs
.\hunt-webshells.ps1 -Baseline  # Baseline IIS web roots (do early!)
.\hunt-webshells.ps1 -Compare   # Diff against baseline (run periodically)
```

---

## Emergency Commands

**Kill attacker session:**

```bash
w && pkill -KILL -u <username>                         # Linux
```

```powershell
query user; logoff <session_id>                        # Windows
```

**Block IP:**

```bash
sudo iptables -I INPUT -s <IP> -j DROP && sudo iptables -I OUTPUT -d <IP> -j DROP
```

```powershell
New-NetFirewallRule -DisplayName "Block" -Direction Inbound -RemoteAddress <IP> -Action Block
```

**Find reverse shells:**

```bash
ss -tnp | grep ESTAB                                   # Linux
```

```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | ft
```

**Change a password:**

```bash
echo "user:newpass" | sudo chpasswd                     # Linux
```

```powershell
net user <username> "NewP@ss!"                          # Windows
```

**Restart a scored service:**

```bash
sudo systemctl restart <service>                        # Linux
```

```powershell
Restart-Service <name>                                  # Windows
```

---

## Rules Reminders

- Do NOT change IP addresses
- Do NOT scan other teams (instant DQ)
- MUST keep ICMP enabled
- MUST report password changes to scoring (except root/admin)
- MAX 3 VM scrubs (with penalty)
- Injects submitted as PDF

---

> **Need more detail?** See [CHECKLIST.md](CHECKLIST.md) (role assignments), [QUICKREF.md](QUICKREF.md) (script reference), [THREAT-HUNTING.md](THREAT-HUNTING.md) (hunting playbook), [TROUBLESHOOTING.md](TROUBLESHOOTING.md) (common issues).
