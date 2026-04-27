# Lab 05 — Active Directory Enumeration with BloodHound

**Category:** Offensive Security / Active Directory Reconnaissance  
**Difficulty:** Intermediate  
**Attacker:** Kali Linux (`10.0.0.117`)  
**Target Domain:** lab.local  
**Domain Controller:** DC01 (`10.0.0.200`)  
**Workstation:** WS01 (`10.0.0.201`)  
**MITRE ATT&CK:** T1069 — Permission Groups Discovery, T1087 — Account Discovery  
**Date:** April 2026

---

## Objective

Use BloodHound Community Edition and SharpHound to perform comprehensive Active Directory enumeration against the lab.local domain. The goal is to map all AD relationships, identify Tier Zero accounts, discover Kerberoastable service accounts, and visualize attack paths, simulating exactly what a threat actor does after gaining initial domain access.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| BloodHound CE v9.0.0 | AD graph analysis and attack path visualization |
| SharpHound v2.12.0 | AD data collector — runs on domain-joined Windows machine |
| Neo4j | Graph database backend for BloodHound |
| Cypher | Query language for extracting specific AD relationships |

---

## Background — What is BloodHound?

BloodHound is an Active Directory reconnaissance tool used by both red teamers and blue teamers to map relationships between users, groups, computers, and permissions in an AD environment. It ingests data collected by SharpHound and renders it as an interactive graph, revealing attack paths that would be nearly impossible to find manually.

From an attacker's perspective BloodHound answers the question: **"I have a low-privilege domain account, what is the fastest path to Domain Admin?"**

From a defender's perspective it answers: **"What attack paths exist in our environment that we need to eliminate?"**

---

## Lab Architecture

```
Kali Linux (10.0.0.117) — BloodHound CE + Neo4j
    │
    │  SharpHound output transferred via SCP
    │
WS01 (10.0.0.201) — SharpHound collector runs here
    │
    │  LDAP queries to enumerate AD
    ▼
DC01 (10.0.0.200) — lab.local domain controller
```

---

## Phase 1 — BloodHound Setup on Kali

### Install and Start

```bash
sudo apt install bloodhound -y
sudo neo4j start
bloodhound-setup  # First time setup — configures Neo4j and PostgreSQL
bloodhound &      # Launch BloodHound GUI
```

BloodHound CE runs as a web application at `http://127.0.0.1:8080`. Neo4j provides the graph database backend at `http://localhost:7474`.

### First Time Configuration

On first launch BloodHound setup:
- Started PostgreSQL service
- Created the bloodhound database
- Started Neo4j
- Prompted for Neo4j password change (default: neo4j/neo4j)

After changing the Neo4j password updated `/etc/bhapi/bhapi.json` with the new credentials before launching BloodHound.

---

## Phase 2 — Data Collection with SharpHound

SharpHound is the data collector component of BloodHound. It must run on a **domain-joined Windows machine** because it uses LDAP to query the domain controller directly.

### Download SharpHound on WS01

Downloaded SharpHound v2.12.0 on WS01 from:
```
https://github.com/SpecterOps/SharpHound/releases/tag/v2.12.0
```

### Run SharpHound

Ran SharpHound from PowerShell as Administrator on WS01:

```powershell
cd C:\Users\Administrator\Downloads\SharpHound
.\SharpHound.exe -c All --domain lab.local --domaincontroller 10.0.0.200
```

**Flag breakdown:**
- `-c All` — collect all data types (ACLs, sessions, group memberships, trusts, GPOs, containers, OUs)
- `--domain lab.local` — target domain
- `--domaincontroller 10.0.0.200` — explicit DC IP

**Output:**
```
SharpHound Enumeration Completed at 11:40 PM on 4/26/2026! Happy Graphing!
Status: 301 objects finished
```

SharpHound collected 301 AD objects in 38 seconds and produced a zip file containing 7 JSON files:

| File | Contents |
|------|---------|
| computers.json | All domain computers |
| containers.json | AD container objects |
| domains.json | Domain trusts and properties |
| gpos.json | Group Policy Objects |
| groups.json | Security groups and memberships |
| ous.json | Organizational Units |
| users.json | All domain user accounts |

### Transfer to Kali

Transferred the SharpHound zip from WS01 to Kali using SCP:

```powershell
# From WS01 PowerShell
scp "C:\Users\Administrator\Downloads\SharpHound\*.zip" kali@10.0.0.117:/home/kali/
```

---

## Phase 3 — Data Ingestion into BloodHound

Uploaded the SharpHound zip file into BloodHound CE via the Quick Upload interface at `http://127.0.0.1:8080`. BloodHound ingested all 7 JSON files and populated the Neo4j graph database with 301 AD objects and their relationships.

---

## Phase 4 — AD Enumeration and Analysis

### Domain Structure Mapping

Using the Pathfinding view mapped the overall domain structure:

```
LAB.LOCAL (Domain)
    ├── ADMINISTRATORS@LAB.LOCAL (Group)
    │       ├── GenericWrite → DOMAIN ADMINS
    │       ├── WriteDacl → DOMAIN ADMINS
    │       └── WriteOwner → DOMAIN ADMINS
    └── USERS@LAB.LOCAL (Container)
            └── Contains → DOMAIN ADMINS
```

**Key finding:** The ADMINISTRATORS group has GenericWrite, WriteDacl, and WriteOwner permissions over Domain Admins — meaning any member of Administrators can effectively control the Domain Admins group.

### User Enumeration

Cypher query to enumerate all domain users:

```cypher
MATCH (u:User) RETURN u
```

**Results — 9 users discovered:**

| User | Tier Zero | Notes |
|------|-----------|-------|
| ADMINISTRATOR@LAB.LOCAL | ✅ | Domain Admin |
| KRBTGT@LAB.LOCAL | ✅ | Kerberos service account |
| JSMITH@LAB.LOCAL | ❌ | Standard user — attacker's initial foothold |
| SJOHNSON@LAB.LOCAL | ❌ | Standard user |
| MDAVIS@LAB.LOCAL | ❌ | Standard user |
| SQLSVC@LAB.LOCAL | ❌ | Service account with SPN |
| GUEST@LAB.LOCAL | ❌ | Disabled guest account |

**Tier Zero accounts** are the highest value targets in any AD environment — compromising them means full domain control.

### Kerberoastable Account Discovery

Cypher query to find all accounts with Service Principal Names (SPNs) set — these are Kerberoasting targets:

```cypher
MATCH (u:User {hasspn:true}) RETURN u
```

**Results — 2 Kerberoastable accounts:**

| Account | Tier Zero | Risk |
|---------|-----------|------|
| KRBTGT@LAB.LOCAL | ✅ | Critical — Golden Ticket attacks |
| SQLSVC@LAB.LOCAL | ❌ | High — weak password, already cracked in Lab 04 |

**This single query instantly identifies every Kerberoastable account in the domain** — the same information that took manual SPN enumeration with Impacket in Lab 04 is now revealed in seconds.

### Attack Path Analysis

Searched for shortest path from jsmith to Domain Admins:

```
Source: JSMITH@LAB.LOCAL
Destination: DOMAIN ADMINS@LAB.LOCAL
Result: Path not found
```

No direct escalation path exists from jsmith to Domain Admins in this environment — confirming the lab AD is not misconfigured with unnecessary privilege assignments. In a real enterprise environment BloodHound commonly finds paths through ACL misconfigurations, nested group memberships, and delegation settings.

---

## How Labs Connect — Full Attack Chain

This lab directly connects to the previous Kerberoasting lab:

```
Lab 05 (BloodHound)          Lab 04 (Kerberoasting)
─────────────────────        ──────────────────────
BloodHound identifies    →   Impacket requests TGS
sqlsvc as Kerberoastable     ticket for sqlsvc

BloodHound shows sqlsvc  →   John the Ripper cracks
has weak credentials         MSSQLSvc2024! hash

BloodHound maps domain   →   Wazuh detects attack
structure for context        via Event ID 4769
```

In a real engagement an attacker would run BloodHound **first** to identify targets, then execute specific attacks like Kerberoasting against those targets.

---

## Defensive Recommendations

| Finding | Risk | Recommendation |
|---------|------|----------------|
| SQLSVC has SPN and weak password | High | Migrate to gMSA — auto-rotating 120-char passwords |
| KRBTGT is Kerberoastable | Critical | This is unavoidable — protect by rotating KRBTGT password twice, monitoring for Golden Ticket attacks |
| ADMINISTRATORS has GenericWrite over Domain Admins | High | Audit group memberships and ACLs regularly — remove unnecessary permissions |
| No path hardening between standard users and DA | Good | Maintain least privilege — no unnecessary group memberships or ACL grants |

---

## Blue Team Value of BloodHound

BloodHound is not just an offensive tool. Security teams use it to:

- **Find attack paths before attackers do** — proactive path elimination
- **Audit ACL misconfigurations** — identify over-permissioned accounts
- **Identify Tier Zero exposure** — who can reach Domain Admin and how
- **Validate remediation** — after fixing a misconfiguration, rerun BloodHound to confirm the path is gone
- **Support penetration testing** — provide evidence of risk to stakeholders

---

## Key Takeaways

- BloodHound reduces AD enumeration from hours of manual work to minutes of automated graph analysis
- A single Cypher query instantly identifies all Kerberoastable accounts across an entire enterprise domain
- Tier Zero account protection is the most critical AD security control — KRBTGT and Administrator must be heavily monitored
- BloodHound is most powerful when run after gaining any domain foothold — even a low-privilege account reveals the entire domain structure
- Defenders should run BloodHound against their own environments regularly to find and eliminate attack paths before attackers exploit them

---

## References

- [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound)
- [SharpHound Releases](https://github.com/SpecterOps/SharpHound/releases)
- [MITRE ATT&CK T1069 — Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
- [MITRE ATT&CK T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [BloodHound Cypher Query Reference](https://support.bloodhoundenterprise.io/hc/en-us/articles/17223823649171)
