> **For the competition-day workflow, see [START-HERE.md](START-HERE.md).**
> **For detailed tool guides, see [MONARCH-GUIDE.md](MONARCH-GUIDE.md) and [DOVETAIL-GUIDE.md](DOVETAIL-GUIDE.md).**
> This file is reference only -- commands, scripts, and tables.

**Team ___** | **Date:** _______________

---

## CREDENTIALS

**Fill in from the competition packet. Do NOT commit passwords to git.**

### Linux Hosts

| Machine | IP | User | Password | Scored Services |
|---------|-----|------|----------|-----------------|
| | | | | |
| | | | | |

### Windows Hosts

| Machine | IP | User | Password | Scored Services |
|---------|-----|------|----------|-----------------|
| | | | | |
| | | | | |

### Network Devices

| Device | IP | Access From | User | Password |
|--------|-----|-------------|------|----------|
| | | | | |

---

## MONARCH COMMANDS (Linux Orchestration)

Start: `cd /opt/ccdc26/monarch && python3 -m monarch`

| Command | Alias | What it does |
|---------|-------|--------------|
| `scan SUBNET PASS` | | Discover hosts via SSH on a subnet |
| `script SCRIPT.sh` | `sc` | Run a script on ALL hosts |
| `script -H HOST SCRIPT.sh` | | Run a script on ONE host |
| `rotate` | | Change all passwords + kick sessions |
| `rotate HOST` | | Change password on one host |
| `rotate -p PASS` | | Set a specific password on all hosts |
| `shell HOST` | `sh` | Interactive SSH shell to a host |
| `list` | `ls` | List all known hosts |
| `add IP PASSWORD` | `a` | Manually add a host |
| `remove HOST` | `rm` | Remove a host |
| `edit HOST password PW` | `e` | Change stored password for a host |
| `edit HOST alias NAME` | | Set a friendly name for a host |
| `upload SCRIPT [HOST]` | `up` | Upload a file to hosts |
| `download PATH [HOST]` | `down` | Download a file/dir from hosts |
| `profile` | `pr` | Profile all hosts (OS, services, ports) |
| `help [CMD]` | `h` | Show help |
| `exit` | | Exit REPL |

---

## DOVETAIL COMMANDS (Windows Orchestration)

From Domain Controller (PowerShell as Admin):

```powershell
cd C:\ccdc26\dovetail

# Connect to all domain-joined Windows machines
.\dovetail.ps1 -Connect -Targets "domain"

# Connect to specific IPs (non-domain / manual)
.\dovetail.ps1 -Connect -Targets "10.0.0.1,10.0.0.2" -NonDomain

# Dispatch a script to all connected hosts
.\dovetail.ps1 -Script .\scripts\01-blitz.ps1

# Dispatch to specific hosts only
.\dovetail.ps1 -Script .\scripts\01-blitz.ps1 -Include "DC01","WEB01"

# Repair broken sessions
.\dovetail.ps1 -Repair
```

---

## SCRIPT REFERENCE

### Linux Scripts (monarch/scripts/)

| Script | Purpose |
|--------|---------|
| `00-snapshot.sh` | Baseline users, crons, services, ports, hashes |
| `01-harden.sh` | SSH lockdown, kernel hardening, permissions, sysctl |
| `02-firewall.sh` | iptables/ufw rules for scored services |
| `03-services.sh` | Harden Apache, Postfix, DNS, MySQL, etc. |
| `04-splunk.sh` | Deploy Splunk universal forwarder |
| `05-monitor.sh` | Deploy file/process/network monitoring |
| `hunt-persistence.sh` | Full persistence scan (cron, services, users, binaries, startup) |
| `hunt-pii.sh` | PII/compliance scanner |
| `ir-triage.sh` | Quick system triage |
| `ir-kill.sh` | Kill attacker sessions |
| `ir-collect.sh` | Forensic evidence collection |
| `ir-isolate.sh` | Network isolation |

### Windows Scripts (dovetail/scripts/)

| Script | Purpose |
|--------|---------|
| `00-snapshot.ps1` | Baseline users, services, tasks, ports, hashes |
| `01-blitz.ps1` | EternalBlue, PrintNightmare, Mimikatz patches. Defender ASR. Disable dangerous services. |
| `02-ad.ps1` | DC only: Zerologon, noPac, Kerberos hardening, privileged group cleanup |
| `03-audit.ps1` | Audit policies, PowerShell logging, command-line auditing, registry SACLs |
| `04-splunk.ps1` | Install Splunk universal forwarder |
| `05-monitor.ps1` | Real-time process/network/session monitoring |
| `hunt-persistence.ps1` | Registry, tasks, WMI, services, COM, SSPs, DLL hijacking |
| `hunt-webshells.ps1` | IIS webshell detection, baseline, and diff |
| `hunt-golden.ps1` | Golden ticket / Kerberos ticket analysis |
| `sanity-check.ps1` | Validate hardening applied correctly |
| `ir-triage.ps1` | Incident triage |
| `ir-kill.ps1` | Kill sessions + block IPs |

### CVEs Patched

| CVE | Name | Script |
|-----|------|--------|
| MS17-010 | EternalBlue | `01-blitz.ps1` |
| CVE-2021-34527 | PrintNightmare | `01-blitz.ps1` |
| CVE-2020-1472 | Zerologon | `02-ad.ps1` |
| CVE-2021-42278/42287 | noPac | `02-ad.ps1` |

---

## EMERGENCY COMMANDS

### Change password

```bash
echo "user:newpass" | sudo chpasswd              # Linux
```

```powershell
net user <username> "NewP@ss!"                   # Windows
```

### Kill attacker session

```bash
w                                                # See who's logged in
pkill -KILL -u <username>                        # Kill all their processes
```

```powershell
query user                                       # See sessions
logoff <session_id>                              # Boot them
```

### Block IP

```bash
sudo iptables -I INPUT -s <IP> -j DROP && sudo iptables -I OUTPUT -d <IP> -j DROP
```

```powershell
New-NetFirewallRule -DisplayName "Block" -Direction Inbound -RemoteAddress <IP> -Action Block
```

### Find reverse shells

```bash
ss -tnp | grep ESTAB
lsof -i -P | grep -E "nc|ncat|bash"
```

```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
```

### Network interface control

```bash
sudo ip link set ens18 down                      # Isolate
sudo ip link set ens18 up                        # Reconnect
```

```powershell
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
Enable-NetAdapter -Name "Ethernet"
```

---

## ENVIRONMENT CONFIG

| File | Platform | Format |
|------|----------|--------|
| `config.env` | Linux/Bash | `export VAR="value"` |
| `config.ps1` | Windows/PS | `$script:EnvConfig` hashtable |

Update these FIRST before running any scripts.

### config.env Fields

| Field | What it is | Where to find it |
|-------|-----------|-----------------|
| `SPLUNK_SERVER` | IP of your Splunk machine | Competition packet |
| `SPLUNK_PORT` | Splunk receiving port | Usually `9997` (don't change) |
| `SPLUNK_VERSION` | Splunk version on server | Run `/opt/splunk/bin/splunk version` on Splunk server |
| `SPLUNK_BUILD` | Splunk build hash | Same command shows the build hash |
| `COMP_USER` | Sudo user created on all Linux hosts | Default: `sysadmin` |
| `CONFIGURED` | Set to `true` when done | Flip to `true` after filling in Splunk values |

> Host IPs, subnets, and firewall IPs are NOT in config.env -- Monarch discovers
> hosts dynamically via `scan`. Record IPs in the QUICKREF credential tables above
> or on your printed packet instead.

---

## RULES

- Do NOT change IP addresses
- Do NOT scan other teams (instant DQ)
- MUST keep ICMP enabled
- MUST report password changes (except root/admin)
- MAX 3 VM scrubs (with penalty)
- Injects submitted as PDF

---

## SCORED SERVICES

| Service | Port | Server |
|---------|------|--------|
| | | |
| | | |
| | | |
