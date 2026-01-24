# MEMORANDUM

| | |
|---|---|
| **TO:** | Executive Management |
| **FROM:** | IT Security Team |
| **DATE:** | January 24, 2026 |
| **RE:** | Incident Retrospective: How This Could Have Been Avoided (BCOM11T) |

---

## Executive Summary

This memo provides a reflection on the recent malware incident affecting our Linux infrastructure. We analyze the attack chain and provide recommendations for both technical controls and policy/procedure improvements that could have prevented or significantly mitigated this incident.

---

## Incident Overview

An employee clicked on a malicious attachment from a social engineering email, leading to a malware infection that spread across our Linux servers via SSH. The malware (`startup_check.py`) used the Paramiko SSH library to propagate to other systems using pre-planted credentials and SSH keys.

**Impact:**
- 3 Linux servers infected
- Potential for lateral movement to critical infrastructure (firewall)
- Credential compromise
- Required emergency incident response

---

## What Could Have Prevented This Incident

### Technical Controls

#### 1. Email Security Gateway

| Control | How It Would Have Helped |
|---------|--------------------------|
| **Attachment sandboxing** | Would have detonated the malicious attachment in isolation before delivery |
| **Link protection** | Would have scanned/blocked malicious URLs in emails |
| **Sender verification (DMARC/DKIM/SPF)** | Could have flagged spoofed sender addresses |

**Recommendation:** Deploy or enhance email security solution with advanced threat protection.

---

#### 2. Endpoint Detection and Response (EDR)

| Control | How It Would Have Helped |
|---------|--------------------------|
| **Behavioral analysis** | Would have detected suspicious Python process spawning SSH connections |
| **Process monitoring** | Would have flagged `/etc/startup_check.py` executing as root |
| **Automated response** | Could have killed malicious process automatically |

**Recommendation:** Deploy EDR solution on all Linux and Windows endpoints.

---

#### 3. SSH Hardening

| Control | How It Would Have Helped |
|---------|--------------------------|
| **Disable root SSH login** | Malware couldn't SSH as root to spread |
| **Key-only authentication** | Password-based spread would fail |
| **SSH key management** | Unknown keys would be detected/blocked |
| **AllowUsers/AllowGroups** | Restrict which users can SSH |

**Recommendation:** Implement SSH hardening policy:
```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
AllowUsers sysadmin
```

---

#### 4. Network Segmentation

| Control | How It Would Have Helped |
|---------|--------------------------|
| **Server-to-server SSH restrictions** | Malware couldn't reach other servers |
| **Micro-segmentation** | Limit lateral movement paths |
| **Jump host requirement** | All SSH must go through monitored bastion |

**Recommendation:** Implement firewall rules restricting SSH:
- Servers should NOT SSH to each other
- SSH only from designated admin workstations/jump hosts

---

#### 5. File Integrity Monitoring (FIM)

| Control | How It Would Have Helped |
|---------|--------------------------|
| **Monitor /etc/ directory** | Alert when startup_check.py created |
| **Baseline comparison** | Detect unauthorized changes |
| **Real-time alerts** | Immediate notification of new files |

**Recommendation:** Deploy file integrity monitoring on all servers (AIDE, OSSEC, or custom solution).

---

#### 6. Application Whitelisting

| Control | How It Would Have Helped |
|---------|--------------------------|
| **Restrict Python execution** | Unauthorized Python scripts blocked |
| **Hash-based whitelisting** | Only approved executables run |

**Recommendation:** Implement application control policies to restrict script execution.

---

#### 7. Privileged Access Management (PAM)

| Control | How It Would Have Helped |
|---------|--------------------------|
| **Credential vaulting** | Root passwords not stored in plaintext |
| **Session monitoring** | Detect/record suspicious privileged activity |
| **Just-in-time access** | Root access only when needed |

**Recommendation:** Implement PAM solution for privileged account management.

---

### Policy and Procedure Controls

#### 1. Security Awareness Training

| Policy Element | How It Would Have Helped |
|----------------|--------------------------|
| **Phishing recognition** | Employee may have identified suspicious email |
| **Reporting procedures** | Faster notification to security team |
| **Regular simulations** | Test and reinforce training |

**Recommendation:** Implement mandatory security awareness training with quarterly phishing simulations.

---

#### 2. Acceptable Use Policy

| Policy Element | How It Would Have Helped |
|----------------|--------------------------|
| **Email attachment handling** | Clear guidance on suspicious attachments |
| **Software installation** | Prohibit unauthorized software (like paramiko) |
| **Reporting requirements** | Mandate reporting of suspicious activity |

**Recommendation:** Update acceptable use policy with specific guidance on email security and unauthorized software.

---

#### 3. Change Management Policy

| Policy Element | How It Would Have Helped |
|----------------|--------------------------|
| **Approval for new services** | Malware systemd service would require approval |
| **Documentation requirements** | Unauthorized changes would be flagged |
| **Audit trail** | Track who made changes and when |

**Recommendation:** Require change tickets for all system modifications, including new services and startup scripts.

---

#### 4. Access Control Policy

| Policy Element | How It Would Have Helped |
|----------------|--------------------------|
| **Principle of least privilege** | Limit root access to essential personnel |
| **SSH key management** | Formal process for SSH key deployment |
| **Regular access reviews** | Detect unauthorized keys/accounts |

**Recommendation:** Implement quarterly access reviews and formal SSH key management process.

---

#### 5. Incident Response Plan

| Policy Element | How It Would Have Helped |
|----------------|--------------------------|
| **Detection procedures** | Faster identification of compromise |
| **Containment steps** | Coordinated isolation of infected systems |
| **Communication plan** | Clear escalation path |

**Recommendation:** Develop and test incident response procedures with regular tabletop exercises.

---

#### 6. Vendor/Software Management Policy

| Policy Element | How It Would Have Helped |
|----------------|--------------------------|
| **Approved software list** | Paramiko wouldn't be authorized |
| **Package installation monitoring** | Alert on pip install commands |
| **Regular audits** | Detect unauthorized packages |

**Recommendation:** Maintain approved software baseline and monitor for deviations.

---

## Mitigation Measures Now in Place

As a result of this incident, we have implemented:

| Control | Status |
|---------|--------|
| File integrity monitoring | **DEPLOYED** |
| Outbound SSH detection script | **DEPLOYED** |
| SSH key audit completed | **COMPLETED** |
| Password rotation | **COMPLETED** |
| Centralized logging (Splunk) | **OPERATIONAL** |
| Firewall deny-any logging | **ENABLED** |

---

## Priority Recommendations Summary

### Immediate (This Week)

1. Disable root SSH login on all servers
2. Implement SSH key management process
3. Deploy email security training reminder

### Short-Term (This Month)

4. Implement network segmentation for server SSH
5. Deploy EDR solution
6. Update security policies (AUP, access control)

### Medium-Term (This Quarter)

7. Implement privileged access management
8. Deploy application whitelisting
9. Conduct incident response tabletop exercise
10. Implement change management for system modifications

---

## Conclusion

This incident could have been prevented or significantly mitigated through a combination of technical controls (SSH hardening, network segmentation, endpoint detection) and policy improvements (security awareness training, access control policies, change management). 

The attack succeeded because it exploited:
- Human vulnerability (phishing)
- Excessive privileges (root SSH enabled)
- Lack of network segmentation (servers could SSH to each other)
- Missing detection capabilities (no FIM or EDR)

By implementing the recommendations in this memo, we can significantly reduce the risk of similar incidents in the future.

---

*Prepared by IT Security Team - January 24, 2026*
