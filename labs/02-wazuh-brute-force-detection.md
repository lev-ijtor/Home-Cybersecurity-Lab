# Lab 02 — Brute Force Detection & Automated Active Response with Wazuh SIEM

**Category:** Defensive Security / SIEM / Detection Engineering  
**Difficulty:** Intermediate  
**Attacker:** Kali Linux (`10.0.0.117`)  
**Target:** VulnTarget Ubuntu (`10.0.0.106`)  
**SIEM:** Wazuh Manager (`10.0.0.166`)  
**Date:** April 2026

---

## Objective

Simulate a real-world SSH brute force attack against a vulnerable Linux host and validate that the Wazuh SIEM correctly detects the attack, generates alerts, and automatically blocks the attacker via active response, all without manual analyst intervention.

This lab demonstrates the full detection-to-response pipeline that a SOC team would rely on to contain credential attacks.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Wazuh 4.x | SIEM — log ingestion, correlation, alerting |
| Wazuh Agent | Endpoint agent on VulnTarget forwarding logs to manager |
| Hydra | SSH brute force attack tool |
| iptables | Firewall used by Wazuh active response to block attacker |
| rockyou.txt | Password wordlist for brute force |

---

## Lab Architecture

```
Kali Linux (10.0.0.117)
    │
    │  SSH brute force (Hydra)
    ▼
VulnTarget (10.0.0.106)
    │
    │  Auth logs forwarded via Wazuh Agent
    ▼
Wazuh Manager (10.0.0.166)
    │
    │  Rule 40111 triggered → active response fired
    ▼
iptables DROP rule pushed back to VulnTarget
    │
    │  Kali IP blocked at firewall level
    ▼
Attack contained automatically
```

---

## Phase 1 — Environment Setup

### Wazuh Manager

Wazuh Manager was deployed on a dedicated Ubuntu 22.04 VM and configured to receive logs from agents across the lab network. The web dashboard runs at `https://10.0.0.166`.

### Wazuh Agent on VulnTarget

The Wazuh agent was installed on VulnTarget and enrolled to the manager, enabling real-time forwarding of system logs including `/var/log/auth.log` — the primary source for SSH authentication events.

Verified agent connectivity from the manager:

```bash
sudo /var/ossec/bin/agent_control -l
```

Agent status confirmed as **Active**.

### Active Response Configuration

Wazuh's built-in `firewall-drop` active response was configured to trigger on rule **40111** (brute force threshold exceeded). When triggered, Wazuh pushes an `iptables` DROP rule to the agent host, blocking the attacker's source IP automatically.

Relevant configuration in `/var/ossec/etc/ossec.conf` on the manager:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>40111</rules_id>
  <timeout>180</timeout>
</active-response>
```

---

## Phase 2 — Attack Simulation

### SSH Brute Force with Hydra

From Kali Linux, launched a brute force attack against the SSH service on VulnTarget using the rockyou wordlist:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.106 -t 4
```

**Flag breakdown:**
- `-l root` — target username
- `-P rockyou.txt` — password wordlist
- `ssh://10.0.0.106` — target protocol and IP
- `-t 4` — 4 parallel threads

Hydra began attempting hundreds of password combinations per minute against the SSH service.

---

## Phase 3 — Detection

### Wazuh Alert Timeline

As Hydra ran, Wazuh ingested the authentication failure logs from VulnTarget in real time and fired the following alert chain:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 5760 | 5 | SSH authentication failure |
| 5758 | 8 | Multiple SSH authentication failures from same source |
| 40111 | 10 | Possible SSH brute force attack — threshold exceeded |

Rule **40111** is the critical threshold rule. Once the number of failed authentication attempts from a single source IP exceeded the configured limit within the detection window, Wazuh classified the activity as a brute force attack and escalated to level 10.

### Alert Details (Wazuh Dashboard)

```
Rule: 40111 - sshd: brute force trying to get access to the system
Level: 10 (Critical)
Source IP: 10.0.0.117
Destination: 10.0.0.106
MITRE ATT&CK: T1110 - Brute Force
```

---

## Phase 4 — Automated Active Response

### Automatic IP Block

Upon rule 40111 firing, Wazuh's active response module automatically executed the `firewall-drop` command on VulnTarget, adding an iptables rule to drop all traffic from the Kali attacker IP:

```bash
# Rule added automatically by Wazuh active response
iptables -I INPUT -s 10.0.0.117 -j DROP
```

### Verification

Confirmed the block was applied on VulnTarget:

```bash
sudo iptables -L INPUT -n
```

Output showed the DROP rule for `10.0.0.117` actively in place.

From Kali, Hydra stalled — no further connection attempts reached the target. The attack was fully contained **without any manual analyst intervention.**

After the configured timeout (180 seconds), Wazuh automatically removed the block, restoring normal connectivity.

---

## Detection Summary

| Indicator | Value |
|-----------|-------|
| Attack Type | SSH Brute Force |
| Source IP | 10.0.0.117 (Kali Linux) |
| Target IP | 10.0.0.106 (VulnTarget) |
| Detection Method | Wazuh rule correlation on auth.log |
| Time to Detect | < 30 seconds from attack start |
| Response | Automatic iptables block via active response |
| MITRE ATT&CK | T1110 — Brute Force |
| Time to Contain | < 60 seconds from attack start |

---

## Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| SSH exposed to internal network with root login enabled | High | Root SSH should be disabled; use key-based auth only |
| No account lockout policy | High | Linux default allows unlimited auth attempts |
| Weak/guessable passwords | High | rockyou.txt wordlist would eventually crack simple passwords |
| No MFA on SSH | Medium | Multi-factor authentication would stop credential attacks entirely |

---

## Defensive Recommendations

1. **Disable root SSH login** — set `PermitRootLogin no` in `/etc/ssh/sshd_config`. Force use of a non-root account with sudo.
2. **Enforce SSH key-based authentication** — disable password auth entirely with `PasswordAuthentication no`. Eliminates brute force as an attack vector.
3. **Implement fail2ban as a secondary layer** — provides host-level brute force protection independent of SIEM.
4. **Restrict SSH access by IP** — use firewall rules to limit which hosts can attempt SSH connections.
5. **Set account lockout policies** — configure `pam_tally2` or `pam_faillock` to lock accounts after N failed attempts.

---

## Key Takeaways

- Wazuh's rule correlation engine detected a brute force attack in under 30 seconds by correlating individual authentication failure events into a high-confidence threat alert.
- The active response pipeline demonstrates how a SIEM can move beyond passive alerting into automated containment — a capability increasingly expected in modern SOC environments.
- MITRE ATT&CK technique T1110 (Brute Force) is one of the most common initial access techniques used in real-world intrusions. Detection rules for this technique are a baseline SOC requirement.
- Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) are key SOC metrics — this lab achieved sub-60-second MTTD and MTTR without analyst involvement.

---

## References

- [Wazuh Active Response Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Hydra Documentation](https://github.com/vanhauser-thc/thc-hydra)
- [Wazuh Rule Reference — Rule 40111](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/)
