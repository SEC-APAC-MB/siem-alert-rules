# Minimum Baseline SIEM Rules

## Overview

The minimum baseline is the essential set of SIEM detection rules that should be deployed **first** on any Oracle Cloud Infrastructure or Microsoft Azure environment. These rules cover the foundational security domains required by NIS2, DORA, PCI-DSS, GDPR, and NIST 800-53.

## What's Included

### Oracle OCI Baseline: 138 rules across 13 domains

### Microsoft Azure Baseline: 121 rules across 13 domains

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

Generated: 2026-09-15T04:05:04.502561+00:00
