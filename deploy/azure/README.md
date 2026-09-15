# Azure Sentinel SIEM Rule Deployment

## Overview

788 SIEM alert rules converted to Azure Sentinel ARM templates. Each rule is an individual JSON file that can be deployed via Azure CLI.

## Prerequisites

1. **Azure CLI** installed and authenticated (`az login`)
2. **Sentinel workspace** enabled on a Log Analytics workspace
3. **Resource group** containing the Log Analytics workspace
4. **Contributor role** on the resource group

## Quick Start

```bash
# Deploy ALL rules
./deploy-all.sh myResourceGroup

# Deploy by priority
./deploy-all.sh myResourceGroup critical    # Start here
./deploy-all.sh myResourceGroup high        # Next
./deploy-all.sh myResourceGroup medium      # Then
./deploy-all.sh myResourceGroup low         # Finally
```

## Priority Choices

### 🔴 Critical — Deploy First (97 rules)
Threat detection core — MITRE ATT&CK techniques, lateral movement chains, AI/LLM security.

| Pack | Rules | What It Detects |
|------|-------|-----------------|
| mitre-attack | 43 | All MITRE ATT&CK tactics (execution, persistence, lateral movement, exfiltration, etc.) |
| lateral-movement-chains | 25 | Multi-stage attack chains (credential theft → lateral movement → data access) |
| lateral-movement | 10 | Direct lateral movement detection (RDP, SMB, PowerShell remoting) |
| ai-security | 27 | AI/LLM attacks (prompt injection, data poisoning, model theft) |
| ai-security-database-rag-redteam | 35 | RAG/AI database red team detection |

### 🟠 High — Deploy Second (173 rules)
Infrastructure and compliance security.

| Pack | Rules | What It Detects |
|------|-------|-----------------|
| database-security | 30 | SQL injection, privilege abuse, data exfiltration from DBs |
| api-security | 16 | API abuse, unauthorized access, rate limit violations |
| compliance-pci-dss | 25 | PCI-DSS regulatory compliance violations |
| ai-security-governance | 25 | AI governance policy violations |
| ai-security-prompt-data-model | 38 | Prompt injection and data model attacks |
| wstg-04-09-auth-errors | 45 | Authentication failures, brute force, session attacks (OWASP WSTG) |

### 🟡 Medium — Deploy Third (250 rules)
Generated detection packs covering specific MITRE tactics and security domains.

| Pack | Rules | What It Detects |
|------|-------|-----------------|
| generated-mitre-attack | 20 | Additional MITRE ATT&CK detections |
| generated-general | 18 | General security anomalies |
| generated-ai_llm_attacks | 16 | LLM-specific attack patterns |
| generated-remote-code-execution | 15 | RCE attempts |
| generated-initial_access | 10 | Initial access techniques |
| generated-persistence | 10 | Persistence mechanisms |
| generated-lateral_movement | 10 | Lateral movement techniques |
| generated-execution | 10 | Code execution detection |
| generated-exfiltration | 10 | Data exfiltration |
| generated-ransomware | 10 | Ransomware indicators |
| generated-reconnaissance | 10 | Recon and discovery |
| generated-privilege-escalation | 6 | Privilege escalation |
| generated-ssrf | 6 | Server-side request forgery |
| generated-endpoint | 9 | Endpoint security |
| generated-cloud_native | 10 | Cloud-native security |
| generated-ics_ot | 10 | ICS/OT security |
| generated-mobile_security | 10 | Mobile security |
| generated-supply_chain | 10 | Supply chain attacks |
| generated-zero_day | 10 | Zero-day indicators |
| generated-network-infrastructure | 5 | Network infrastructure |
| generated-database | 4 | Database anomalies |
| generated-cloud-container | 3 | Container security |
| generated-sql-injection | 1 | SQL injection |
| generated-web-application | 1 | Web app attacks |
| wstg-01-03 | 20 | OWASP WSTG info gathering |
| wstg-04-06 | 20 | OWASP WSTG auth testing |
| wstg-07-09 | 32 | OWASP WSTG session management |
| wstg-10-business-logic | 8 | OWASP WSTG business logic |
| mobile-security | 10 | Mobile security threats |

### 🟢 Low — Deploy Last (155 rules)
GitHub advisory-based vulnerability detection rules. Useful but lower priority for active threat detection.

| Pack | Rules | What It Detects |
|------|-------|-----------------|
| github-advisory-rules | 155 | CVE-based detection from GitHub Security Advisories |

## Individual Rule Deployment

Each rule is a standalone ARM template. Deploy any single rule:

```bash
az deployment group create \
  --resource-group myResourceGroup \
  --template-file arm-templates/AZ-MITRE-0600_arm.json
```

## Rule File Format

Each ARM template contains:
- `apiVersion: 2024-03-01`
- `type: Microsoft.SecurityInsights/alertRules`
- Properties: displayName, query (KQL), severity, queryFrequency, queryPeriod, triggerOperator, triggerThreshold, tactics, techniques

## Summary

| Status | Count |
|--------|-------|
| DEPLOY-AS-IS | 787 |
| NEEDS-TUNING | 1 |
| NEEDS-REWRITE | 0 |
| WON'T-WORK | 0 |
| **Total** | **788** |

## Notes

- All queries use KQL (Kusto Query Language) for Azure Sentinel
- Table references: AzureActivity, SecurityEvent, SecurityAlert, SigninLogs, AzureDiagnostics, etc.
- Rules with `NEEDS-TUNING` status have tuning notes in the description field
- Rules are independent — deploy as many or as few as needed
- Duplicated rule IDs will fail on re-deploy (delete first or skip existing)