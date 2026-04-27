# Lab 02 - Brute Force Detection and Automated Active Response with Wazuh SIEM

**Category:** Defensive Security / SIEM / Detection Engineering  
**Difficulty:** Intermediate  
**Attacker:** Kali Linux (`10.0.0.117`)  
**Target:** VulnTarget Ubuntu (`10.0.0.106`)  
**SIEM:** Wazuh Manager (`10.0.0.166`)  
**Date:** April 2026

---

## Overview

Simulated an SSH brute force attack against a vulnerable Linux host to validate that Wazuh correctly detects the attack, generates alerts, and automatically blocks the attacker via active response without any manual analyst intervention. This covers the full detection-to-response pipeline that a SOC team would rely on to contain credential attacks.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Wazuh 4.x | SIEM - log ingestion, correlation, alerting |
| Wazuh Agent | Endpoint agent on VulnTarget forwarding logs to manager |
| Hydra | SSH brute force attack tool |
| iptables | Firewall used by Wazuh active response to block attacker |
| rockyou.txt | Password wordlist for brute force |

---

## Lab Architecture

```
Kali Linux (10.0.0.117)
    |
    |  SSH brute force (Hydra)
    v
VulnTarget (10.0.0.106)
    |
    |  Auth logs forwarded via Wazuh Agent
    v
Wazuh Manager (10.0.0.166)
    |
    |  Rule 40111 triggered -> active response fired
    v
iptables DROP rule pushed back to VulnTarget
    |
    |  Kali IP blocked at firewall level
    v
Attack contained automatically
```

---

## Phase 1 - Environment Setup

Wazuh Manager runs on a dedicated Ubuntu 22.04 VM and receives logs from agents across the lab network. The dashboard is accessible at `https://10.0.0.166`.

The Wazuh agent on VulnTarget was installed and enrolled to the manager, enabling real-time forwarding of system logs including `/var/log/auth.log`, which is the primary source for SSH authentication events. Verified agent connectivity:

```bash
sudo /var/ossec/bin/agent_control -l
```

Agent status confirmed as Active.

The built-in `firewall-drop` active response was configured to trigger on rule 40111, which is the brute force threshold rule. When it fires, Wazuh pushes an iptables DROP rule to the agent host and blocks the attacker's source IP automatically. The relevant config in `/var/ossec/etc/ossec.conf`:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>40111</rules_id>
  <timeout>180</timeout>
</active-response>
```

---

## Phase 2 - Attack Simulation

Launched Hydra from Kali against the SSH service on VulnTarget:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.106 -t 4
```

Hydra started hitting hundreds of password combinations per minute against the SSH service.

---

## Phase 3 - Detection

As Hydra ran, Wazuh ingested the authentication failure logs from VulnTarget in real time. The alert chain fired in sequence:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 5760 | 5 | SSH authentication failure |
| 5758 | 8 | Multiple SSH authentication failures from same source |
| 40111 | 10 | Possible SSH brute force attack - threshold exceeded |

Once the failed authentication count from a single source IP crossed the threshold within the detection window, Wazuh escalated to level 10 and classified it as a brute force attack.

```
Rule: 40111 - sshd: brute force trying to get access to the system
Level: 10 (Critical)
Source IP: 10.0.0.117
Destination: 10.0.0.106
MITRE ATT&CK: T1110 - Brute Force
```

---

## Phase 4 - Automated Active Response

The moment rule 40111 fired, Wazuh's active response module executed `firewall-drop` on VulnTarget and added an iptables rule dropping all traffic from the Kali IP:

```bash
iptables -I INPUT -s 10.0.0.117 -j DROP
```

Confirmed the block on VulnTarget:

```bash
sudo iptables -L INPUT -n
```

The DROP rule for `10.0.0.117` was in place. Back on Kali, Hydra stalled with no further connections reaching the target. The attack was fully contained without any manual intervention.

After the 180 second timeout, Wazuh automatically removed the block and restored normal connectivity.

---

## Detection Summary

| Indicator | Value |
|-----------|-------|
| Attack Type | SSH Brute Force |
| Source IP | 10.0.0.117 (Kali Linux) |
| Target IP | 10.0.0.106 (VulnTarget) |
| Detection Method | Wazuh rule correlation on auth.log |
| Time to Detect | Under 30 seconds from attack start |
| Response | Automatic iptables block via active response |
| MITRE ATT&CK | T1110 - Brute Force |
| Time to Contain | Under 60 seconds from attack start |

---

## Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| SSH exposed with root login enabled | High | Root SSH should be disabled; use key-based auth only |
| No account lockout policy | High | Linux default allows unlimited auth attempts |
| Weak/guessable passwords | High | rockyou.txt would eventually crack simple passwords |
| No MFA on SSH | Medium | MFA would stop credential attacks entirely |

---

## Defensive Recommendations

Root SSH login should be disabled by setting `PermitRootLogin no` in `/etc/ssh/sshd_config`. If possible, password auth should be disabled entirely with `PasswordAuthentication no` and replaced with key-based authentication. That alone eliminates brute force as an attack vector since there is no password to guess.

For additional layering, fail2ban provides host-level brute force protection independent of the SIEM, and firewall rules can restrict which source IPs are even allowed to attempt SSH connections in the first place. On the account side, `pam_faillock` can lock accounts after a set number of failed attempts.

---

## References

- [Wazuh Active Response Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/)
- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Hydra Documentation](https://github.com/vanhauser-thc/thc-hydra)
- [Wazuh Rule Reference - Rule 40111](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/)
