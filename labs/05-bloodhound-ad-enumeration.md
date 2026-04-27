# Lab 05 - Active Directory Enumeration with BloodHound

**Category:** Offensive Security / Active Directory Reconnaissance  
**Difficulty:** Intermediate  
**Attacker:** Kali Linux (`10.0.0.117`)  
**Target Domain:** lab.local  
**Domain Controller:** DC01 (`10.0.0.200`)  
**Workstation:** WS01 (`10.0.0.201`)  
**MITRE ATT&CK:** T1069 - Permission Groups Discovery, T1087 - Account Discovery  
**Date:** April 2026

---

## Overview

Used BloodHound Community Edition and SharpHound to enumerate the lab.local Active Directory domain, map all AD relationships, identify Tier Zero accounts, find Kerberoastable service accounts, and visualize attack paths. This is the same reconnaissance process a threat actor would run after gaining initial domain access.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| BloodHound CE v9.0.0 | AD graph analysis and attack path visualization |
| SharpHound v2.12.0 | AD data collector - runs on domain-joined Windows machine |
| Neo4j | Graph database backend for BloodHound |
| Cypher | Query language for extracting specific AD relationships |

---

## Background

Active Directory is essentially a massive database of relationships between users, groups, computers, and permissions. In a large environment there are thousands of these relationships and manually auditing them is not realistic.

BloodHound ingests all of those relationships and turns them into a visual graph. It then uses graph theory to calculate the shortest path between any two nodes, for example the fastest route from a compromised low-privilege account to Domain Admin. From a red team perspective it answers "what can I do with this account." From a blue team perspective it answers "what attack paths exist in our environment that we need to close."

It has two components. SharpHound runs on a domain-joined Windows machine and uses LDAP to pull all AD relationship data, outputting a set of JSON files. BloodHound takes those files, loads them into a Neo4j graph database, and lets you query and visualize the results.

---

## Lab Architecture

```
Kali Linux (10.0.0.117) - BloodHound CE + Neo4j
    |
    |  SharpHound output transferred via SCP
    |
WS01 (10.0.0.201) - SharpHound collector runs here
    |
    |  LDAP queries to enumerate AD
    v
DC01 (10.0.0.200) - lab.local domain controller
```

---

## Phase 1 - BloodHound Setup on Kali

```bash
sudo apt install bloodhound -y
sudo neo4j start
bloodhound-setup
bloodhound &
```

BloodHound CE runs as a web app at `http://127.0.0.1:8080`. The first time setup configures Neo4j and PostgreSQL, creates the bloodhound database, and prompts for a password change on the default neo4j/neo4j credentials. After changing the password, updated `/etc/bhapi/bhapi.json` with the new credentials before launching BloodHound.

---

## Phase 2 - Data Collection with SharpHound

SharpHound has to run on a domain-joined Windows machine because it queries the domain controller via LDAP.

Ran SharpHound from PowerShell as Administrator:

```powershell
cd C:\Users\Administrator\Downloads\SharpHound
.\SharpHound.exe -c All --domain lab.local --domaincontroller 10.0.0.200
```

Output:

```
SharpHound Enumeration Completed at 11:40 PM on 4/26/2026! Happy Graphing!
Status: 301 objects finished
```

301 AD objects collected in 38 seconds across 7 JSON files covering computers, containers, domains, GPOs, groups, OUs, and users.

Transferred the output zip from WS01 to Kali:

```powershell
scp "C:\Users\Administrator\Downloads\SharpHound\*.zip" kali@10.0.0.117:/home/kali/
```

---

## Phase 3 - Data Ingestion

Uploaded the zip into BloodHound CE via the Quick Upload interface. BloodHound ingested all 7 JSON files and populated the graph database with 301 objects and their relationships.

---

## Phase 4 - Analysis

### Domain Structure

The Pathfinding view revealed the overall domain structure:

```
LAB.LOCAL (Domain)
    |- ADMINISTRATORS@LAB.LOCAL (Group)
    |       |- GenericWrite -> DOMAIN ADMINS
    |       |- WriteDacl -> DOMAIN ADMINS
    |       +- WriteOwner -> DOMAIN ADMINS
    +- USERS@LAB.LOCAL (Container)
            +- Contains -> DOMAIN ADMINS
```

The ADMINISTRATORS group has GenericWrite, WriteDacl, and WriteOwner permissions over Domain Admins. That means anyone who can get into the Administrators group can effectively control Domain Admins.

### User Enumeration

```cypher
MATCH (u:User) RETURN u
```

9 users returned. ADMINISTRATOR and KRBTGT came back flagged as Tier Zero, meaning highest privilege in the domain. The rest, including jsmith, sjohnson, mdavis, sqlsvc, and guest, came back as standard accounts.

| User | Tier Zero | Notes |
|------|-----------|-------|
| ADMINISTRATOR@LAB.LOCAL | Yes | Domain Admin |
| KRBTGT@LAB.LOCAL | Yes | Kerberos service account |
| JSMITH@LAB.LOCAL | No | Standard user - attacker's initial foothold |
| SJOHNSON@LAB.LOCAL | No | Standard user |
| MDAVIS@LAB.LOCAL | No | Standard user |
| SQLSVC@LAB.LOCAL | No | Service account with SPN |
| GUEST@LAB.LOCAL | No | Disabled guest account |

### Kerberoastable Account Discovery

```cypher
MATCH (u:User {hasspn:true}) RETURN u
```

Two accounts came back: KRBTGT and SQLSVC. Both have SPNs registered, which makes them Kerberoasting targets. This is the same sqlsvc account that was manually identified and attacked in Lab 04 using Impacket. BloodHound found it in one query in seconds.

### Attack Path Analysis

Searched for the shortest path from jsmith to Domain Admins. No path was found, which is expected in this lab since jsmith has no unusual permissions or group memberships that would create an escalation path. In a real enterprise environment this kind of search commonly surfaces paths through ACL misconfigurations or nested group memberships that nobody knew existed.

---

## How This Connects to Other Labs

In a real engagement BloodHound would run first to identify targets, then specific attacks get executed against those targets. The workflow looks like this:

BloodHound identifies sqlsvc as Kerberoastable, which leads to the Impacket attack in Lab 04. BloodHound also flags ADMINISTRATOR as a Tier Zero target, which connects to the Pass-the-Hash attack in Lab 06 where that credential gets dumped from memory and used for lateral movement.

---

## Defensive Recommendations

The sqlsvc situation should be addressed by migrating to a Group Managed Service Account. gMSA passwords are 120 characters, randomly generated, and rotated by Active Directory automatically. There is nothing to Kerberoast.

KRBTGT being Kerberoastable is unavoidable since it is a built-in account, but the impact can be limited by rotating the KRBTGT password twice and monitoring for Golden Ticket activity.

The GenericWrite/WriteDacl/WriteOwner permissions the ADMINISTRATORS group has over Domain Admins should be reviewed in any environment. Regular ACL audits and strict least-privilege group management would catch this kind of misconfiguration before an attacker does.

Running BloodHound proactively against your own environment is one of the most useful things a security team can do. Finding and closing attack paths before they get exploited is significantly cheaper than responding to an incident.

---

## References

- [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound)
- [SharpHound Releases](https://github.com/SpecterOps/SharpHound/releases)
- [MITRE ATT&CK T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
- [MITRE ATT&CK T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [BloodHound Cypher Query Reference](https://support.bloodhoundenterprise.io/hc/en-us/articles/17223823649171)
