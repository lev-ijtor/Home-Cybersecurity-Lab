# Home Cybersecurity Lab

A personal cybersecurity home lab built to develop and document hands-on skills in penetration testing, SIEM detection engineering, incident response, and Active Directory security. All projects are performed in an isolated lab environment.

---

## Network Overview

```
Internet
    |
[Google Nest Router - 192.168.86.1]
    |
[Linux PC - Ubuntu] -- Gateway / Router / Pi-hole DNS
    |   10.0.0.1
    |
[TP-Link Switch]
    |- Windows PC (Hypervisor Host) -- 10.0.0.111
    |       |- Kali Linux (Attacker)     10.0.0.117
    |       |- Wazuh SIEM (Ubuntu)       10.0.0.166
    |       |- VulnTarget (Ubuntu)       10.0.0.106
    |       |- Metasploitable 2          10.0.0.142
    |       |- DC01 - Windows Server 2022 10.0.0.200
    |       +- WS01 - Workstation VM     10.0.0.201
    +-- Linux PC                         10.0.0.1
```

---

## Lab Inventory

| Host | OS | IP | Role |
|------|----|----|------|
| Linux PC | Ubuntu 22.04 | 10.0.0.1 | Gateway, Pi-hole DNS/DHCP, Nextcloud |
| Windows PC | Windows 11 | 10.0.0.111 | VirtualBox Hypervisor Host |
| Kali Linux | Kali Rolling | 10.0.0.117 | Attacker Machine |
| Wazuh Manager | Ubuntu 22.04 | 10.0.0.166 | SIEM / Detection Engineering |
| VulnTarget | Ubuntu 22.04 | 10.0.0.106 | Intentionally Vulnerable Target |
| Metasploitable 2 | Ubuntu 8.04 | 10.0.0.142 | Legacy Vulnerable Target |
| DC01 | Windows Server 2022 | 10.0.0.200 | Active Directory Domain Controller (lab.local) |
| WS01 | Windows Server 2022 | 10.0.0.201 | Domain-Joined Workstation |

---

## Projects and Write-Ups

| # | Project | Category | Skills Demonstrated |
|---|---------|----------|-------------------|
| 01 | [Metasploitable 2 Penetration Test](labs/01-metasploitable-pentest.md) | Offensive | Nmap, Metasploit, vsftpd 2.3.4 exploit, privilege escalation, password cracking |
| 02 | [Wazuh Brute Force Detection and Active Response](labs/02-wazuh-brute-force-detection.md) | Defensive / SIEM | Wazuh rules, active response, Hydra, SSH log analysis |
| 03 | [Active Directory Lab Setup](labs/03-active-directory-setup.md) | Infrastructure | AD DS, domain users, SPNs, Group Policy, DNS |
| 04 | [Kerberoasting Attack and Detection](labs/04-kerberoasting.md) | Offensive + Defensive | Impacket, TGS ticket extraction, Wazuh detection, custom SIEM rules, MITRE T1558.003 |
| 05 | [BloodHound AD Enumeration](labs/05-bloodhound-ad-enumeration.md) | Reconnaissance | BloodHound CE, SharpHound, Cypher queries, attack path mapping, Tier Zero identification |
| 06 | [Pass-the-Hash Attack and Detection](labs/06-pass-the-hash.md) | Offensive + Defensive | Mimikatz, NTLM hash extraction, Impacket psexec, Wazuh detection, MITRE T1550.002 |

More labs added continuously. See commit history for progress.

---

## Tools and Technologies

**Offensive Security**
Kali Linux, Nmap, Metasploit Framework, Hydra, John the Ripper, Impacket, Mimikatz, BloodHound, SharpHound

**SIEM and Detection**
Wazuh 4.x, Splunk (professional experience), custom detection rules, active response, Windows Event Log analysis

**Infrastructure**
VirtualBox, iptables, Pi-hole, Ubuntu Server, Windows Server 2022, Active Directory, Tailscale VPN

**Scripting and Admin**
Bash, Python, Linux system administration, Windows Server administration, PowerShell

---

## Lab Goals

- [x] Build isolated lab network with custom routing and DNS
- [x] Deploy Wazuh SIEM with agent monitoring across multiple hosts
- [x] Complete full penetration test on Metasploitable 2
- [x] Detect and auto-block brute force attacks with Wazuh active response
- [x] Build Active Directory environment with realistic domain users
- [x] Complete Kerberoasting attack and detection lab
- [x] Configure domain-joined workstation (WS01) for lateral movement practice
- [x] Write custom Wazuh detection rules for AD attack techniques
- [x] Document full incident response exercise with IR report
- [x] Run BloodHound AD enumeration and attack path analysis
- [x] Execute Pass-the-Hash lateral movement and detect with Wazuh
- [x] Configure Tailscale VPN for secure remote lab access
- [ ] Password spraying attack and detection
- [ ] PowerShell execution detection engineering
- [ ] Cloud lab extension (AWS/Azure)

---

## Certifications

- CompTIA Security+
- CompTIA Network+
- Cisco CyberOps Associate
- Splunk Core Certified User
- Google Cybersecurity Professional Certificate

---

## About

**Levi Torres** - CS Graduate (UTSA, B.S. Computer Science, Dec 2025) | 2x Cybersecurity Analyst Intern @ CGI Federal (DoD clients) | Targeting SOC Analyst and Security Engineer roles.

[LinkedIn](https://linkedin.com/in/torres-levi) • levi.torres0826@gmail.com
