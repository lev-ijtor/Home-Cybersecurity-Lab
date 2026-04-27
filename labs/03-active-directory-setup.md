# Lab 03 - Active Directory Lab Setup

**Category:** Infrastructure / Active Directory  
**Difficulty:** Intermediate  
**Domain:** lab.local  
**Domain Controller:** DC01 (`10.0.0.200`) - Windows Server 2022  
**Workstation:** WS01 (`10.0.0.201`) - Windows Server 2022  
**Date:** April 2026

---

## Overview

Built a realistic Active Directory environment from scratch to use as a target for AD-based attack and detection labs. The environment mirrors a small enterprise network with a domain controller, a domain-joined workstation, realistic user accounts, and a service account configured for Kerberoasting practice.

---

## Infrastructure

```
lab.local (Active Directory Domain)
    |
    |- DC01 (10.0.0.200) - Domain Controller
    |       - Windows Server 2022
    |       - AD DS, DNS, Kerberos
    |       - Wazuh Agent (forwarding Security logs)
    |
    +- WS01 (10.0.0.201) - Domain Workstation
            - Windows Server 2022
            - Domain joined to lab.local
            - Wazuh Agent installed
            - RDP enabled
```

---

## Phase 1 - Domain Controller Setup (DC01)

### VM Specifications

| Setting | Value |
|---------|-------|
| OS | Windows Server 2022 Evaluation |
| RAM | 4GB |
| CPU | 2 cores |
| Disk | 60GB |
| IP | 10.0.0.200 (static) |
| Network | Bridged - Realtek 2.5GbE |

### Active Directory Domain Services Installation

Opened Server Manager, added the Active Directory Domain Services role, then promoted the server to a domain controller with a new forest:

```
Deployment: Add a new forest
Root domain name: lab.local
Forest functional level: Windows Server 2016
Domain functional level: Windows Server 2016
DNS Server: enabled
DSRM password: (set during install)
```

Server rebooted and joined as DC01.lab.local.

### Static IP Configuration

```
IP Address:      10.0.0.200
Subnet Mask:     255.255.255.0
Default Gateway: 10.0.0.1
DNS Server:      10.0.0.200 (itself)
```

---

## Phase 2 - Domain User Creation

Created realistic domain users to simulate an enterprise environment. Weak passwords were intentionally set for lab attack practice:

```powershell
net user jsmith Password123! /add /domain
net user sjohnson Welcome1! /add /domain
net user mdavis Summer2024! /add /domain
net user sqlsvc MSSQLSvc2024! /add /domain
```

Password policy was relaxed to allow these passwords in the lab:

```cmd
net accounts /minpwlen:0 /maxpwage:unlimited /minpwage:0 /uniquepw:0 /domain
```

This configuration is intentionally insecure and exists only for lab purposes.

---

## Phase 3 - Service Principal Name Configuration

Configured sqlsvc as a service account with an SPN to simulate a real SQL Server service account, which is a common Kerberoasting target in enterprise environments.

Activated the account and set the SPN:

```cmd
net user sqlsvc /active:yes /domain
setspn -A MSSQLSvc/dc01.lab.local:1433 sqlsvc
```

Verified it was registered correctly:

```cmd
setspn -L sqlsvc
```

```
Registered ServicePrincipalNames for CN=SQL Service,CN=Users,DC=lab,DC=local:
    MSSQLSvc/dc01.lab.local:1433
    MSSQLSvc/dc01.lab.local:1443
```

Any domain user can now request a TGS ticket for sqlsvc, which enables the Kerberoasting attack covered in Lab 04.

---

## Phase 4 - Workstation Setup (WS01)

### VM Specifications

| Setting | Value |
|---------|-------|
| OS | Windows Server 2022 Evaluation |
| RAM | 4GB |
| CPU | 2 cores |
| Disk | 60GB |
| IP | 10.0.0.201 (static) |
| Network | Bridged - Realtek 2.5GbE |

### Static IP Configuration

```
IP Address:      10.0.0.201
Subnet Mask:     255.255.255.0
Default Gateway: 10.0.0.1
DNS Server:      10.0.0.200 (DC01)
```

DNS must point to DC01. Without this, the domain join will fail because WS01 cannot resolve lab.local.

### Domain Join

Right-click Start, System, Advanced system settings, Computer Name tab, Change:

```
Computer name: WS01
Member of Domain: lab.local
```

Entered Administrator credentials when prompted and restarted.

### Verification

```cmd
whoami
lab\jsmith

hostname
WS01
```

Domain user jsmith authenticated successfully on WS01, confirming the join worked.

---

## Phase 5 - Wazuh Agent Deployment

Deployed Wazuh agents on both DC01 and WS01 to get SIEM visibility across the AD environment.

For each machine, went to the Wazuh dashboard, Deploy new agent, selected Windows MSI, set the manager IP to `10.0.0.166`, and gave the agent a name matching the hostname. Ran the generated PowerShell command as Administrator on each machine and started the service:

```powershell
NET START WazuhSvc
```

Also enabled Kerberos audit logging on DC01 so that Event ID 4769 gets generated for Kerberos ticket requests:

```cmd
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

Without this, the Kerberoasting detection in Lab 04 would not work.

RDP was also enabled on WS01 for remote management:

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

---

## Domain User Summary

| Username | Password | Role | Notes |
|----------|----------|------|-------|
| jsmith | Password123! | Standard user | Initial foothold account |
| sjohnson | Welcome1! | Standard user | Password spray target |
| mdavis | Summer2024! | Standard user | Password spray target |
| sqlsvc | MSSQLSvc2024! | Service account | SPN set - Kerberoasting target |
| Administrator | (strong) | Domain Admin | DC management only |

---

## Security Notes

This lab intentionally replicates common enterprise misconfigurations. Service accounts like sqlsvc should use randomly generated passwords of 25 or more characters, or better yet be replaced entirely with Group Managed Service Accounts which handle password rotation automatically. RC4 Kerberos encryption should be disabled via Group Policy in any production environment to prevent Kerberoasting entirely. Domain Admin accounts should never be used interactively on workstations since credential caching on low-security machines is exactly what the Pass-the-Hash lab in Lab 06 exploits.

---

## References

- [Microsoft AD DS Installation Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services)
- [Wazuh Windows Agent Deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
- [Service Principal Names Overview](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names)
