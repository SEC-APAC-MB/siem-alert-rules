# Minimum Baseline SIEM Rules

## Overview

The minimum baseline is the essential set of SIEM detection rules that should be deployed **first** on any Oracle Cloud Infrastructure or Microsoft Azure environment. These rules cover the foundational security domains required by NIS2, DORA, PCI-DSS, GDPR, and NIST 800-53.

## What's Included

### Oracle OCI Baseline: 149 rules across 13 domains

### Microsoft Azure Baseline: 132 rules across 13 domains

## Domains Covered

| Domain | Weight | Description |
|--------|--------|-------------|
| Authentication & Initial Access | CRITICAL | Brute force, failed logins, external access attempts |
| Privilege Escalation | CRITICAL | Admin role changes, policy modifications, unauthorized elevation |
| Lateral Movement | HIGH | Internal SSH/RDP, process execution across hosts |
| Data Exfiltration | HIGH | Large data transfers, unusual outbound traffic |
| Persistence | HIGH | New user creation, API keys, scheduled tasks, backdoors |
| Ransomware Detection | CRITICAL | Mass file encryption, storage spikes, ransom indicators |
| Reconnaissance & Scanning | MEDIUM | Port scans, dropped connections, service enumeration |
| Database Security | HIGH | SQL injection, failed connections, unauthorized queries |
| Supply Chain Security | HIGH | Image tampering, unauthorized deployments, dependency attacks |
| Zero-Day & Anomalous Activity | CRITICAL | Unexpected ports, anomalous patterns, novel exploits |
| SQL Injection | HIGH | Injection patterns, union selects, OR 1=1 attempts |
| SSRF | HIGH | Internal IP access, metadata endpoint queries |
| Remote Code Execution | CRITICAL | Code execution exploits, CVE-based RCE attempts |
| Execution & Process Activity | HIGH | PowerShell abuse, suspicious process creation |

## Compliance Coverage

| Framework | Coverage |
|-----------|----------|
| EU NIS2 Directive | Art. 15(1) — Risk management measures |
| EU DORA | Art. 5-11 — ICT risk management, detection, incident response |
| PCI-DSS v4.0 | Req. 6, 7, 8, 10, 11, 12 |
| GDPR | Art. 32, 33 — Security of processing, breach notification |
| NIST 800-53 Rev 5 | AC, AU, CM, CP, IA, SA, SC, SI, SR families |

## Deployment

### Oracle OCI
```bash
cd deployments/baseline/oracle/
# Edit deployment-config.yaml with your compartment and region
./deploy.sh --dry-run     # Validate first
./deploy.sh               # Deploy for real
```

### Microsoft Azure
```bash
cd deployments/baseline/azure/
# Edit deployment-config.yaml with your subscription and workspace
./deploy.sh --dry-run     # Validate first
./deploy.sh               # Deploy for real
```

## Why Minimum Baseline?

The minimum baseline provides:
1. **Immediate coverage** — 14 critical security domains from day one
2. **Regulatory compliance** — satisfies core detection requirements for NIS2, DORA, PCI-DSS, GDPR
3. **Low noise** — curated to avoid alert fatigue while covering essential threats
4. **Fast deployment** — focused rule set that deploys in minutes, not hours

After baseline deployment, expand coverage with the full rule sets or regulation-specific packages (NIS2, DORA).

## Contents

```
deployments/baseline/
├── README.md                        # This file
├── oracle/
│   ├── baseline-rules.json          # All Oracle baseline rules
│   ├── compliance-mapping.json      # Framework-to-rule mapping
│   ├── deployment-config.yaml       # Configuration template
│   └── deploy.sh                    # Deployment script
└── azure/
    ├── baseline-rules.json          # All Azure baseline rules
    ├── compliance-mapping.json      # Framework-to-rule mapping
    ├── deployment-config.yaml       # Configuration template
    └── deploy.sh                    # Deployment script
```

## Oracle OCI Baseline — Complete Rule List (149 Rules)

| # | Rule ID | Name | Severity | MITRE | Compliance |
|---|---------|------|----------|-------|------------|
| | **Authentication & Initial Access** (CRITICAL) — 10 rules | | | | |
| 1 | OCI-INITIAL_ACCESS-127 | Phishing Link Detection | MEDIUM | — | — |
| 2 | OCI-INITIAL_ACCESS-128 | Spear-Phishing Attachment | MEDIUM | — | — |
| 3 | OCI-INITIAL_ACCESS-129 | Valid Account Abuse | MEDIUM | — | — |
| 4 | OCI-INITIAL_ACCESS-130 | Exploit Public-Facing Application | MEDIUM | — | — |
| 5 | OCI-INITIAL_ACCESS-131 | Supply Chain Compromise | MEDIUM | — | — |
| 6 | OCI-INITIAL_ACCESS-132 | VPN Appliance Exploitation | MEDIUM | — | — |
| 7 | OCI-INITIAL_ACCESS-133 | Trusted Relationship Abuse | MEDIUM | — | — |
| 8 | OCI-INITIAL_ACCESS-134 | Drive-by Compromise | MEDIUM | — | — |
| 9 | OCI-INITIAL_ACCESS-135 | External Remote Services Brute Force | MEDIUM | — | — |
| 10 | OCI-INITIAL_ACCESS-136 | Hardware Additions | MEDIUM | — | — |
| | | | | | |
| | **Privilege Escalation** (CRITICAL) — 19 rules | | | | |
| 11 | OCI-PRIVILEGE-ESCALATION-001 | CVE-2026-86060 — RouterOS Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 12 | OCI-PRIVILEGE-ESCALATION-002 | CVE-2026-53362 — Kernel Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 13 | OCI-PRIVILEGE-ESCALATION-004 | CVE-2026-53362 — Kernel Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 14 | OCI-PRIVILEGE-ESCALATION-005 | CVE-2015-3246 — Libuser Exploitation | MEDIUM | T1498, T1548, T1110, T1078 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 15 | OCI-PRIVILEGE-ESCALATION-006 | CVE-2015-5287 — ABRT Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 16 | OCI-PRIVILEGE-ESCALATION-007 | CVE-2015-3246 — Libuser Exploitation | MEDIUM | T1110, T1078, T1498, T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 17 | OCI-PRIVILEGE-ESCALATION-008 | CVE-2015-5287 — ABRT Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 18 | OCI-PRIVILEGE-ESCALATION-011 | CVE-2026-53362 — Kernel Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 19 | OCI-PRIVILEGE-ESCALATION-012 | CVE-2026-53362 — Kernel Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 20 | OCI-PRIVILEGE-ESCALATION-014 | CVE-2015-3246 — Libuser Exploitation | MEDIUM | T1110, T1078, T1498, T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 21 | OCI-PRIVILEGE-ESCALATION-015 | CVE-2015-5287 — ABRT Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 22 | OCI-PRIVILEGE-ESCALATION-016 | CVE-2015-5287 — ABRT Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 23 | OCI-PRIVILEGE-ESCALATION-019 | CVE-2015-3246 — Libuser Exploitation | MEDIUM | T1498, T1078, T1548, T1110 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 24 | OCI-PRIVILEGE-ESCALATION-020 | CVE-2015-5287 — ABRT Exploitation | MEDIUM | T1548 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 25 | GHADV-1056 | ArcadeDB: Privilege escalation via reader role | MEDIUM | T1548 | — |
| 26 | GHADV-2197 | Strimzi: Unrestricted access to all Secrets | MEDIUM | T1548 | — |
| 27 | GHADV-2198 | Strimzi: Cross-namespace privilege escalation | MEDIUM | T1548 | — |
| 28 | GHADV-3084 | Jenkins Job Import Plugin permission bypass | MEDIUM | T1548 | — |
| 29 | GHADV-3086 | Jenkins AppSpider Plugin permission bypass | MEDIUM | T1548 | — |
| | | | | | |
| | **Ransomware Detection** (CRITICAL) — 10 rules | | | | |
| 30 | OCI-RANSOMWARE-077 | Mass File Encryption Pattern | MEDIUM | — | — |
| 31 | OCI-RANSOMWARE-078 | Shadow Copy Deletion | MEDIUM | — | — |
| 32 | OCI-RANSOMWARE-079 | Ransom Note Creation | MEDIUM | — | — |
| 33 | OCI-RANSOMWARE-080 | Volume Shadow Copy Tampering | MEDIUM | — | — |
| 34 | OCI-RANSOMWARE-081 | Backup Deletion via Vssadmin | MEDIUM | — | — |
| 35 | OCI-RANSOMWARE-082 | Ransomware C2 Beacon Pattern | MEDIUM | — | — |
| 36 | OCI-RANSOMWARE-083 | Mimikatz Credential Dumping Pre-Encryption | MEDIUM | — | — |
| 37 | OCI-RANSOMWARE-084 | Lateral Movement via PsExec/WMI | MEDIUM | — | — |
| 38 | OCI-RANSOMWARE-085 | Scheduled Task Creation for Encryption | MEDIUM | — | — |
| 39 | OCI-RANSOMWARE-086 | Registry Run Key Persistence for Ransomware | MEDIUM | — | — |
| | | | | | |
| | **Zero-Day & Anomalous Activity** (CRITICAL) — 10 rules | | | | |
| 40 | OCI-ZERO_DAY-087 | Unexpected Process Execution from Web Directory | MEDIUM | — | — |
| 41 | OCI-ZERO_DAY-088 | Anomalous Child Process from Service | MEDIUM | — | — |
| 42 | OCI-ZERO_DAY-089 | Unusual Network Connection from System Process | MEDIUM | — | — |
| 43 | OCI-ZERO_DAY-090 | Memory Injection Pattern Detection | MEDIUM | — | — |
| 44 | OCI-ZERO_DAY-091 | Unexpected DLL Loading | MEDIUM | — | — |
| 45 | OCI-ZERO_DAY-092 | Abnormal Token Privilege Elevation | MEDIUM | — | — |
| 46 | OCI-ZERO_DAY-093 | Process Hollowing Indicator | MEDIUM | — | — |
| 47 | OCI-ZERO_DAY-094 | Reflective DLL Injection | MEDIUM | — | — |
| 48 | OCI-ZERO_DAY-095 | Unusual Named Pipe Activity | MEDIUM | — | — |
| 49 | OCI-ZERO_DAY-096 | Anomalous Service Installation | MEDIUM | — | — |
| | | | | | |
| | **Lateral Movement** (HIGH) — 20 rules | | | | |
| 50 | OCI-LATERAL_MOVEMENT-167 | Pass-the-Hash Detection | MEDIUM | — | — |
| 51 | OCI-LATERAL_MOVEMENT-168 | Pass-the-Ticket Detection | MEDIUM | — | — |
| 52 | OCI-LATERAL_MOVEMENT-169 | Lateral Movement via PsExec | MEDIUM | — | — |
| 53 | OCI-LATERAL_MOVEMENT-170 | SSH Lateral Movement | MEDIUM | — | — |
| 54 | OCI-LATERAL_MOVEMENT-171 | RDP Lateral Movement | MEDIUM | — | — |
| 55 | OCI-LATERAL_MOVEMENT-172 | Kubernetes Pod-to-Pod Lateral Movement | MEDIUM | — | — |
| 56 | OCI-LATERAL_MOVEMENT-173 | DCSync Attack | MEDIUM | — | — |
| 57 | OCI-LATERAL_MOVEMENT-174 | Golden Ticket Attack | MEDIUM | — | — |
| 58 | OCI-LATERAL_MOVEMENT-175 | Kerberoasting | MEDIUM | — | — |
| 59 | OCI-LATERAL_MOVEMENT-176 | ARP Spoofing Detection | MEDIUM | — | — |
| 60 | OCI-LAT-0700 | RDP Followed by Credential Access | MEDIUM | T1021.001, T1555 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 61 | OCI-LAT-0701 | SSH Followed by Privilege Escalation | MEDIUM | T1021.006, T1548 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 62 | OCI-LAT-0702 | SMB Share Access Followed by File Encryption | MEDIUM | T1021.002, T1486 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 63 | OCI-LAT-0703 | WMI Remote Execution Followed by Persistence | MEDIUM | T1546.003, T1547.001 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 64 | OCI-LAT-0704 | PsExec Followed by Discovery | MEDIUM | T1021.002, T1082 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 65 | OCI-LAT-0705 | PowerShell Remoting Followed by Credential Dumping | MEDIUM | T1059.001, T1003.001 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 66 | OCI-LAT-0706 | WinRM Followed by Defense Evasion | MEDIUM | T1021.001, T1027 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 67 | OCI-LAT-0707 | Kerberoasting Followed by Lateral Movement | MEDIUM | T1558.001, T1021 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 68 | OCI-LAT-0708 | DCSync Attack Chain | MEDIUM | T1003.006, T1558 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| 69 | OCI-LAT-0709 | Pass-the-Hash Detection (Chain) | MEDIUM | T1550.002 | NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8 |
| | | | | | |
| | **Data Exfiltration** (HIGH) — 10 rules | | | | |
| 70 | OCI-EXFILTRATION-157 | DNS Tunneling Detection | MEDIUM | — | — |
| 71 | OCI-EXFILTRATION-158 | Large Data Transfer to Cloud Storage | MEDIUM | — | — |
| 72 | OCI-EXFILTRATION-159 | ICMP Data Exfiltration | MEDIUM | — | — |
| 73 | OCI-EXFILTRATION-160 | HTTPS Data Exfiltration | MEDIUM | — | — |
| 74 | OCI-EXFILTRATION-161 | Email Data Exfiltration | MEDIUM | — | — |
| 75 | OCI-EXFILTRATION-162 | Database Bulk Export | MEDIUM | — | — |
| 76 | OCI-EXFILTRATION-163 | Screen Capture Data Theft | MEDIUM | — | — |
| 77 | OCI-EXFILTRATION-164 | Steganography Detection | MEDIUM | — | — |
| 78 | OCI-EXFILTRATION-165 | Web Shell Data Exfiltration | MEDIUM | — | — |
| 79 | OCI-EXFILTRATION-166 | Clipboard Data Theft | MEDIUM | — | — |
| | | | | | |
| | **Persistence** (HIGH) — 10 rules | | | | |
| 80 | OCI-PERSISTENCE-147 | Registry Run Key Modification | MEDIUM | — | — |
| 81 | OCI-PERSISTENCE-148 | Scheduled Task Persistence | MEDIUM | — | — |
| 82 | OCI-PERSISTENCE-149 | Service Creation for Persistence | MEDIUM | — | — |
| 83 | OCI-PERSISTENCE-150 | WMI Event Subscription | MEDIUM | — | — |
| 84 | OCI-PERSISTENCE-151 | DLL Search Order Hijacking | MEDIUM | — | — |
| 85 | OCI-PERSISTENCE-152 | Browser Extension Persistence | MEDIUM | — | — |
| 86 | OCI-PERSISTENCE-153 | Kubernetes CronJob Persistence | MEDIUM | — | — |
| 87 | OCI-PERSISTENCE-154 | Cloud IAM Backdoor | MEDIUM | — | — |
| 88 | OCI-PERSISTENCE-155 | SSH Authorized Key Injection | MEDIUM | — | — |
| 89 | OCI-PERSISTENCE-156 | Cron Job Persistence (Linux) | MEDIUM | — | — |
| | | | | | |
| | **Database Security** (HIGH) — 7 rules | | | | |
| 90 | OCI-DATABASE-001 | CVE-2026-21962 — Weblogic Proxy Plug-in | MEDIUM | T1110, T1078 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 91 | OCI-DATABASE-009 | CVE-2019-1068 — SQL Server RCE | MEDIUM | T1059, T1190 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 92 | OCI-DATABASE-011 | CVE-2026-21962 — Weblogic Proxy Plug-in | MEDIUM | T1110, T1078 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 93 | OCI-DATABASE-013 | CVE-2026-21962 — Weblogic Proxy Plug-in | MEDIUM | T1110, T1078 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 94 | OCI-DATABASE-018 | CVE-2019-1068 — SQL Server RCE | MEDIUM | T1059, T1190 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 95 | OCI-DATABASE-019 | CVE-2019-1068 — SQL Server RCE | MEDIUM | T1190, T1059 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 96 | OCI-DATABASE-020 | CVE-2026-21962 — Weblogic Proxy Plug-in | MEDIUM | T1110, T1078 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| | | | | | |
| | **Supply Chain Security** (HIGH) — 10 rules | | | | |
| 97 | OCI-SUPPLY_CHAIN-057 | Dependency Confusion Attack | MEDIUM | — | — |
| 98 | OCI-SUPPLY_CHAIN-058 | Typosquatting Package Install | MEDIUM | — | — |
| 99 | OCI-SUPPLY_CHAIN-059 | Compromised CI/CD Pipeline | MEDIUM | — | — |
| 100 | OCI-SUPPLY_CHAIN-060 | Malicious NPM/PyPI Package | MEDIUM | — | — |
| 101 | OCI-SUPPLY_CHAIN-061 | Container Image Tampering | MEDIUM | — | — |
| 102 | OCI-SUPPLY_CHAIN-062 | Compromised Update Server | MEDIUM | — | — |
| 103 | OCI-SUPPLY_CHAIN-063 | Build Pipeline Injection | MEDIUM | — | — |
| 104 | OCI-SUPPLY_CHAIN-064 | Secret Leakage in CI Logs | MEDIUM | — | — |
| 105 | OCI-SUPPLY_CHAIN-065 | Unsigned Artifact Deployment | MEDIUM | — | — |
| 106 | OCI-SUPPLY_CHAIN-066 | Dependency Version Pinning Bypass | MEDIUM | — | — |
| | | | | | |
| | **SQL Injection** (HIGH) — 5 rules | | | | |
| 107 | OCI-SQL-INJECTION-013 | CVE-2026-72898 — Metabase Exploitation | MEDIUM | T1190, T1110, T1078 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 108 | GHADV-1336 | OpenRemote Authenticated SQL Injection | MEDIUM | T1190 | — |
| 109 | GHADV-2220 | LangChain4j SQL injection via metadata filters | MEDIUM | T1190 | — |
| 110 | GHADV-4503 | appsmith SQL Injection via Unsafe DROP TABLE | MEDIUM | T1190 | — |
| 111 | GHADV-4547 | Spring AI SQL Injection in CosmosDBVectorStore | MEDIUM | T1190 | — |
| | | | | | |
| | **Server-Side Request Forgery (SSRF)** (HIGH) — 18 rules | | | | |
| 112 | OCI-SSRF-005 | CVE-2026-64849 — MLflow Exploitation | MEDIUM | T1190 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 113 | OCI-SSRF-006 | CVE-2026-83548 — SMA1000 Appliances | MEDIUM | T1110, T1078, T1592, T1190, T1213 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 114 | OCI-SSRF-007 | CVE-2026-83548 — SMA1000 Appliances | MEDIUM | T1592, T1078, T1213, T1190, T1110 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 115 | OCI-SSRF-011 | CVE-2026-83548 — SMA1000 Appliances | MEDIUM | T1213, T1078, T1592, T1190, T1110 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 116 | OCI-SSRF-015 | CVE-2026-64849 — MLflow Exploitation | MEDIUM | T1190 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 117 | OCI-SSRF-017 | CVE-2026-64849 — MLflow Exploitation | MEDIUM | T1190 | PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A |
| 118 | GHADV-0576 | java-client Network Pivot via directConnect | MEDIUM | T1190 | — |
| 119 | GHADV-1820 | jackson-databind SSRF via DNS resolution | MEDIUM | T1190 | — |
| 120 | GHADV-1888 | OpenAM SSRF via /sessionservice | MEDIUM | T1190 | — |
| 121 | GHADV-2660 | Spring Framework SSRF via UriComponentsBuilder | MEDIUM | T1190 | — |
| 122 | GHADV-2875 | Apache Fesod SSRF via UrlImageConverter | MEDIUM | T1190 | — |
| 123 | GHADV-2947 | CC-Tweaked SSRF Protection Bypass with NAT64 | MEDIUM | T1190 | — |
| 124 | GHADV-3090 | Jenkins LDAP Plugin follows LDAP referrals | MEDIUM | T1190 | — |
| 125 | GHADV-3092 | Jenkins AD Plugin follows LDAP referrals | MEDIUM | T1190 | — |
| 126 | GHADV-3470 | Spring AI MCP Unvalidated URL Fetching | MEDIUM | T1190 | — |
| 127 | GHADV-4281 | XWiki PlantUML SSRF via 'server' parameter | MEDIUM | T1190 | — |
| 128 | GHADV-4308 | Eclipse BaSyx Java Server SDK SSRF | MEDIUM | T1190 | — |
| 129 | GHADV-4441 | Apache Neethi SSRF via PolicyReference API | MEDIUM | T1190 | — |
| | | | | | |
| | **Execution & Process Activity** (HIGH) — 10 rules | | | | |
| 130 | OCI-EXECUTION-137 | PowerShell Suspicious Execution | MEDIUM | — | — |
| 131 | OCI-EXECUTION-138 | WMI Remote Execution | MEDIUM | — | — |
| 132 | OCI-EXECUTION-139 | Scheduled Task/At Job Creation | MEDIUM | — | — |
| 133 | OCI-EXECUTION-140 | LSASS Memory Dumping | MEDIUM | — | — |
| 134 | OCI-EXECUTION-141 | Living-off-the-Land Binary (LOLBins) | MEDIUM | — | — |
| 135 | OCI-EXECUTION-142 | CMSTP Execution | MEDIUM | — | — |
| 136 | OCI-EXECUTION-143 | Remote Service Session Hijacking | MEDIUM | — | — |
| 137 | OCI-EXECUTION-144 | Container Admin Escape | MEDIUM | — | — |
| 138 | OCI-EXECUTION-145 | Kubernetes Exec into Pod | MEDIUM | — | — |
| 139 | OCI-EXECUTION-146 | SQL Command Execution via Web App | MEDIUM | — | — |
| | | | | | |
| | **Reconnaissance & Scanning** (MEDIUM) — 10 rules | | | | |
| 140 | OCI-RECONNAISSANCE-117 | Active Directory Domain Enumeration | MEDIUM | — | — |
| 141 | OCI-RECONNAISSANCE-118 | Network Service Discovery (Nmap/Masscan) | MEDIUM | — | — |
| 142 | OCI-RECONNAISSANCE-119 | DNS Zone Transfer Attempt | MEDIUM | — | — |
| 143 | OCI-RECONNAISSANCE-120 | Web Technology Fingerprinting | MEDIUM | — | — |
| 144 | OCI-RECONNAISSANCE-121 | Cloud Asset Enumeration | MEDIUM | — | — |
| 145 | OCI-RECONNAISSANCE-122 | SSL/TLS Certificate Reconnaissance | MEDIUM | — | — |
| 146 | OCI-RECONNAISSANCE-123 | API Endpoint Discovery | MEDIUM | — | — |
| 147 | OCI-RECONNAISSANCE-124 | Email Harvesting & Phishing Prep | MEDIUM | — | — |
| 148 | OCI-RECONNAISSANCE-125 | SNMP Community String Brute Force | MEDIUM | — | — |
| 149 | OCI-RECONNAISSANCE-126 | Kubernetes API Server Recon | MEDIUM | — | — |
| | | | | | |
| | **TOTAL** | **149 rules** | | | |

Generated: 2026-09-14T05:21:23.446801+00:00
