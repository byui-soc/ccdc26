> **For the step-by-step workflow, see [START-HERE.md](START-HERE.md).**
> This checklist provides additional detail and role assignments.

# CCDC26 Flag Drop Checklist

**Team ___** | **Flag Drop:** _______________

---

## Pre-Competition (Night Before / Morning Of)

- [ ] Verify all team accounts on NISE and Stadium portals
- [ ] Print QUICKREF.md -- one copy per team member
- [ ] Assign machines to people (see Role Assignments below)

---

## Phase 1: First 5 Minutes (Critical)

**Goal:** Get onto all machines, change passwords, prevent immediate attacker access.

### Linux Controller (1 person)

- [ ] VNC into Linux workstation
- [ ] Clone toolkit: `git clone https://github.com/byui-soc/ccdc26.git /opt/ccdc26`
- [ ] Configure: `cd /opt/ccdc26 && sudo ./deploy.sh --configure`
- [ ] Start Monarch: `cd monarch && python3 -m monarch repl`
- [ ] Scan: `scan SUBNET PASSWORD`
- [ ] Snapshot: `script 00-snapshot.sh`

### Windows Machines (2-3 people in parallel)

- [ ] VNC into each Windows machine
- [ ] **Immediately** change admin password: `net user administrator "YourTeamP@ss!"`
- [ ] Deploy toolkit (see Step 0 in START-HERE.md)
- [ ] Run snapshot: `cd C:\ccdc26\dovetail\scripts && .\00-snapshot.ps1`

---

## Phase 2: Password Reset (Minutes 5-10)

### Linux (from Monarch REPL)

```
> rotate
```

Changes ALL Linux user passwords + kicks active sessions.

### Windows (each machine)

```powershell
Get-LocalUser | Where-Object {$_.Enabled} | ForEach-Object { net user $_.Name "YourTeamP@ss!" }
```

- [ ] **Report password changes** to scoring (required per rules!)

---

## Phase 3: Initial Hardening (Minutes 10-20)

### Linux (from Monarch REPL)

```
> script 01-harden.sh
> script 02-firewall.sh
> script 03-services.sh
```

### Windows (each machine)

```powershell
cd C:\ccdc26\dovetail\scripts
.\01-blitz.ps1                  # All Windows machines
.\02-ad.ps1                     # Domain Controller ONLY
```

**Or via Dovetail from DC:**

```powershell
cd C:\ccdc26\dovetail
.\dovetail.ps1 -Connect -Targets "domain"
.\dovetail.ps1 -Script .\scripts\01-blitz.ps1
```

---

## Phase 4: Verify Scored Services (Minutes 20-25)

**Do NOT skip this.** Check that hardening didn't break anything.

| Service | Machine | Port | Quick Test |
|---------|---------|------|------------|
| HTTP | [ecom server] | 80 | `curl http://<ip>` |
| HTTP | [Windows web server] | 80 | Browser check |
| SMTP | [webmail server] | 25 | `telnet <ip> 25` |
| POP3 | [webmail server] | 110 | `telnet <ip> 110` |
| DNS | [AD/DNS server] | 53 | `nslookup <domain> <ip>` |

- [ ] Test each service from the scoring engine's perspective
- [ ] Check Stadium portal for service status
- [ ] If a service is down: restart it, check logs, undo firewall rule if needed

---

## Phase 5: Firewall Configuration (Minutes 25-35)

> **CRITICAL from prelims**: Linux and Windows were on SEPARATE subnets.
> If this is the case again, by default Linux CANNOT reach Windows. You MUST add cross-zone rules
> or Splunk, toolkit transfers, and all cross-zone management will fail.

### Cisco FTD (Windows zone) -- Network Lead from Windows workstation

- [ ] Browse to `https://<cisco-ftd-ip>`, login with packet credentials
- [ ] Add rule: Scoring (Any -> Windows subnet, ports 53/80/443/21, ICMP)
- [ ] Add rule: Linux -> Windows (Linux subnet -> Windows subnet, ports 5985/9997)
- [ ] Add rule: Windows -> Linux (Windows subnet -> Linux subnet, ports 22/9997/8000)
- [ ] Change default password
- [ ] Commit/deploy changes

### Palo Alto (Linux zone) -- Network Lead from Linux workstation

- [ ] Browse to `https://<palo-alto-ip>`, login with packet credentials
- [ ] Add rule: Scoring (Any -> Linux subnet, ports 25/80/110/443, ICMP)
- [ ] Add rule: Windows -> Linux (Windows subnet -> Linux subnet, ports 22/9997)
- [ ] Add rule: Linux -> Windows (Linux subnet -> Windows subnet, ports 5985/9997)
- [ ] Change default password
- [ ] Commit changes

### Router (VyOS)

- [ ] Login with packet credentials
- [ ] Change password
- [ ] Verify routing between zones works (do NOT add ACLs until services are green)

### Windows Firewall (each Windows machine)

```powershell
New-NetFirewallRule -DisplayName "Allow Linux Subnet" -Direction Inbound -RemoteAddress LINUX_SUBNET/24 -Action Allow
```

### Verify cross-zone works

```bash
ping <windows-ip>                          # From Linux
nc -zv <windows-ip> 5985                   # WinRM
```
```powershell
Test-NetConnection <linux-splunk-ip> -Port 9997   # From Windows
```

---

## Phase 6: SIEM + Monitoring (Minutes 35-45)

### Linux (from Monarch REPL)

```
> script 04-splunk.sh
> script 05-monitor.sh
```

### Windows (each machine)

```powershell
cd C:\ccdc26\dovetail\scripts
.\03-audit.ps1
.\04-splunk.ps1
.\05-monitor.ps1
```

- [ ] Verify Splunk server is receiving data
- [ ] Start monitoring on all Windows machines
- [ ] Baseline IIS web roots: `.\hunt-webshells.ps1 -Baseline`

---

## Phase 7: Persistence Hunting (When Stable)

### Linux

```
> script hunt-persistence.sh
```

### Windows

```powershell
cd C:\ccdc26\dovetail\scripts
.\hunt-persistence.ps1
.\hunt-webshells.ps1 -Compare
```

- [ ] Hunt persistence on AD/DNS server
- [ ] Hunt persistence on Windows web server
- [ ] Hunt persistence on all Linux hosts
- [ ] Scan for webshells on IIS servers

---

## Ongoing Priorities

1. **Monitor Stadium portal** for service status
2. **Watch for injects** on NISE portal
3. **Check `w` / `query user`** periodically for unauthorized sessions
4. **Re-run persistence hunts** after incidents
5. **Scan for webshells** periodically: `.\hunt-webshells.ps1 -Compare`
6. **Check monitoring** alerts: `.\05-monitor.ps1 -Status`

---

## Role Assignments (Suggested)

| Role | Primary Tasks | Machines |
|------|---------------|----------|
| **Linux Lead** | Monarch controller, Linux hardening, Splunk server | Ubuntu Wks (controller), Ecom, Webmail, Splunk |
| **Windows Lead** | AD hardening, Dovetail dispatch, DNS service | AD/DNS 2019, Win11 Wks |
| **Web Lead** | IIS hardening, web services, webshell hunting | Web 2019 |
| **Network Lead** | Firewall rules, VyOS | Palo Alto, Cisco FTD, VyOS |
| **Inject/Flex** | Handle injects, backup IR | Float between tasks |

---

## Machine Quick Reference

**Fill in from competition packet. See also `config.env`.**

### Linux Hosts

| Machine | IP | User | Scored Services |
|---------|-----|------|-----------------|
| | | | |
| | | | |
| | | | |

### Windows Hosts

| Machine | IP | User | Scored Services |
|---------|-----|------|-----------------|
| | | | |
| | | | |
| | | | |

### Network Devices

| Device | IP | Access From | User |
|--------|-----|-------------|------|
| | | | |
| | | | |
| | | | |

---

## Rules Reminders

- Do NOT change IP addresses
- Do NOT scan other teams (instant DQ)
- MUST keep ICMP enabled
- MUST report password changes (except root/admin)
- MAX 3 VM scrubs (with penalty)
- Injects submitted as PDF
