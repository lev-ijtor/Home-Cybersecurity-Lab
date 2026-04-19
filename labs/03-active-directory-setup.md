# Lab 03 — Active Directory Lab Setup

**Category:** Infrastructure / Active Directory  
**Difficulty:** Intermediate  
**Domain:** lab.local  
**Domain Controller:** DC01 (`10.0.0.200`) — Windows Server 2022  
**Workstation:** WS01 (`10.0.0.201`) — Windows Server 2022  
**Date:** April 2026

---

## Objective

Build a realistic Active Directory environment from scratch to serve as a target for AD-based attack and detection labs. The environment mirrors a small enterprise network with a domain controller, domain-joined workstation, realistic user accounts, and a service account configured for Kerberoasting.

---

## Infrastructure Overview

```
lab.local (Active Directory Domain)
    │
    ├── DC01 (10.0.0.200) — Domain Controller
    │       - Windows Server 2022
    │       - AD DS, DNS, Kerberos
    │       - Wazuh Agent (forwarding Security logs)
    │
    └── WS01 (10.0.0.201) — Domain Workstation
            - Windows Server 2022
            - Domain joined to lab.local
            - Wazuh Agent installed
            - RDP enabled
```

---

## Phase 1 — Domain Controller Setup (DC01)

### VM Specifications

| Setting | Value |
|---------|-------|
| OS | Windows Server 2022 Evaluation |
| RAM | 4GB |
| CPU | 2 cores |
| Disk | 60GB |
| IP | 10.0.0.200 (static) |
| Network | Bridged — Realtek 2.5GbE |

### Install Active Directory Domain Services

Opened Server Manager → Add Roles and Features → selected **Active Directory Domain Services**.

After installation, promoted the server to a Domain Controller:

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
IP Address:     10.0.0.200
Subnet Mask:    255.255.255.0
Default Gateway: 10.0.0.1
DNS Server:     10.0.0.200 (itself)
```

---

## Phase 2 — Domain User Creation

Created realistic domain users to simulate an enterprise environment. Weak passwords were intentionally set for lab attack practice.

```powershell
net user jsmith Password123! /add /domain
net user sjohnson Welcome1! /add /domain
net user mdavis Summer2024! /add /domain
net user sqlsvc MSSQLSvc2024! /add /domain
```

## Phase 3 — Service Principal Name (SPN) Configuration

Configured `sqlsvc` as a service account with an SPN to simulate a real SQL Server service account — a common Kerberoasting target in enterprise environments.

First activated the account:
```cmd
net user sqlsvc /active:yes /domain
```

Set the SPN:
```cmd
setspn -A MSSQLSvc/dc01.lab.local:1433 sqlsvc
```

Verified:
```cmd
setspn -L sqlsvc
```

Output:
```
Registered ServicePrincipalNames for CN=SQL Service,CN=Users,DC=lab,DC=local:
    MSSQLSvc/dc01.lab.local:1433
    MSSQLSvc/dc01.lab.local:1443
```

Any domain user can now request a TGS ticket for sqlsvc — enabling Kerberoasting.

---

## Phase 4 — Workstation Setup (WS01)

### VM Specifications

| Setting | Value |
|---------|-------|
| OS | Windows Server 2022 Evaluation |
| RAM | 4GB |
| CPU | 2 cores |
| Disk | 60GB |
| IP | 10.0.0.201 (static) |
| Network | Bridged — Realtek 2.5GbE |

### Static IP Configuration

```
IP Address:     10.0.0.201
Subnet Mask:    255.255.255.0
Default Gateway: 10.0.0.1
DNS Server:     10.0.0.200 (DC01)
```

DNS must point to DC01 — required for domain join to resolve lab.local.

### Domain Join

Right-click Start → System → Advanced system settings → Computer Name → Change:

```
Computer name: WS01
Member of Domain: lab.local
```

Entered Administrator credentials when prompted. Restarted after successful join.

### Verified Domain Join

```cmd
whoami
lab\jsmith

hostname
WS01

nltest /sc_verify:lab.local
```

Domain user `jsmith` successfully authenticated on WS01.

---

## Phase 5 — Wazuh Agent Deployment

Deployed Wazuh agents on both DC01 and WS01 to enable SIEM visibility across the AD environment.

### DC01 Agent

Deployed via Wazuh dashboard → Deploy new agent → Windows MSI:

```
Manager IP: 10.0.0.166
Agent name: DC01
```

Ran generated PowerShell command as Administrator on DC01. Started service:
```powershell
NET START WazuhSvc
```

### Enabled Kerberos Audit Policy on DC01

Required to generate Event ID 4769 (Kerberos service ticket requests):

```cmd
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

### WS01 Agent

Same deployment process with agent name set to `WS01`. Enabled RDP for remote management:

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

---

## Domain User Summary

| Username | Password | Role | Notes |
|----------|----------|------|-------|
| jsmith | Password123! | Standard user | Used as attacker's initial foothold |
| sjohnson | Welcome1! | Standard user | Password spray target |
| mdavis | Summer2024! | Standard user | Password spray target |
| sqlsvc | MSSQLSvc2024! | Service account | SPN set — Kerberoasting target |
| Administrator | (strong) | Domain Admin | DC management only |

---

## Security Notes

This lab intentionally replicates common enterprise misconfigurations:

- **Weak service account passwords** — Service accounts are high-value targets. Passwords should be 25+ characters, randomly generated, and managed via a PAM solution or Group Managed Service Accounts (gMSA).
- **RC4 encryption allowed** — Modern AD should enforce AES-only Kerberos encryption via Group Policy to prevent Kerberoasting.
- **No tiered administration** — In production, Domain Admin accounts should never be used on workstations. Privileged Access Workstations (PAWs) should be used instead.

---

## References

- [Microsoft AD DS Installation Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services)
- [Wazuh Windows Agent Deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
- [Service Principal Names Overview](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names)
