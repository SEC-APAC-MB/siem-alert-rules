# Oracle OCI Cloud Guard Detector Recipe Deployment

## Overview

1,102 SIEM alert rules converted to OCI Cloud Guard Detector Recipes. Each rule is an individual JSON file importable via OCI CLI or Terraform.

## Prerequisites

1. **OCI CLI** installed and configured (`oci setup config`)
2. **Cloud Guard** enabled in the target compartment
3. **Compartment OCID** where detector recipes will be created
4. **Security Admin role** or equivalent permissions

## Quick Start

```bash
# Deploy ALL rules
./deploy-all.sh ocid1.compartment.oc1..aaaa...

# Deploy by priority
./deploy-all.sh ocid1.compartment.oc1..aaaa... critical    # Start here
./deploy-all.sh ocid1.compartment.oc1..aaaa... high        # Next
./deploy-all.sh ocid1.compartment.oc1..aaaa... medium      # Then
./deploy-all.sh ocid1.compartment.oc1..aaaa... low         # Finally
```

## Alternative: Terraform Deployment

```bash
cd terraform/
terraform init
terraform plan -var="compartment_id=ocid1.compartment.oc1..aaaa..."
terraform apply -var="compartment_id=ocid1.compartment.oc1..aaaa..."
```

Each rule also has an individual `.tf.json` file for selective deployment.

## Priority Choices

### 🔴 Critical — Deploy First (193 rules)
Threat detection core — MITRE ATT&CK techniques, lateral movement chains, AI/LLM security.

| Pack | Rules | What It Detects |
|------|-------|-----------------|
| mitre-attack | 43 | All MITRE ATT&CK tactics (execution, persistence, lateral movement, exfiltration) |
| lateral-movement-chains | 25 | Multi-stage attack chains (credential theft → lateral movement → data access) |
| lateral-movement | 10 | Direct lateral movement detection |
| ai-security | 27 | AI/LLM attacks (prompt injection, data poisoning, model theft) |
| ai-security-database-rag-redteam | 35 | RAG/AI database red team detection |
| ai-security-governance | 25 | AI governance policy violations |
| ai-security-prompt-data-model | 38 | Prompt injection and data model attacks |

### 🟠 High — Deploy Second (213 rules)
Infrastructure and compliance security.

| Pack | Rules | What It Detects |
|------|-------|-----------------|
| database-security | 30 | SQL injection, privilege abuse, data exfiltration |
| api-security | 16 | API abuse, unauthorized access |
| compliance-pci-dss | 25 | PCI-DSS regulatory compliance violations |
| wstg-04-09-auth-errors | 45 | Authentication failures, brute force (OWASP WSTG) |
| wstg-07-09 | 32 | OWASP WSTG session management |
| wstg-04-06 | 20 | OWASP WSTG authentication testing |
| wstg-01-03 | 20 | OWASP WSTG information gathering |
| wstg-10-business-logic | 8 | OWASP WSTG business logic |
| mobile-security | 10 | Mobile security threats |
| github-advisory-rules | 469 | CVE-based detection from GitHub Security Advisories |

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

### 🟢 Low — Deploy Last (469 rules)
GitHub advisory-based vulnerability detection rules.

| Pack | Rules | What It Detects |
|------|-------|-----------------|
| github-advisory-rules | 469 | CVE-based detection from GitHub Security Advisories |

## Individual Rule Deployment

### Via OCI CLI
```bash
oci cloud-guard detector-recipe create \
  --from-json file://detector-recipes/OCI-MITRE-0600_detector_recipe.json \
  --compartment-id ocid1.compartment.oc1..aaaa...
```

### Via Terraform
```bash
cd terraform/
terraform apply -target=oci_cloud_guard_detector_recipe.oci_mitre_0600
```

## Detector Recipe Format

Each detector recipe JSON contains:
- `displayName`: Rule name with ID prefix
- `detector`: OCI_ACTIVITY (audit-based), OCI_CONFIGURATION (config-based), or OCI_THREAT
- `severity`: CRITICAL, HIGH, MEDIUM, or LOW
- `conditionGroups`: Conditions that trigger the detector
- `dataSourceDetails`: Data source (OCI_AUDIT / OCI_MONITORING), namespace, query
- `mappings`: MITRE ATT&CK tactics/techniques, compliance frameworks
- `isEnabled`: true

## Summary

| Status | Count |
|--------|-------|
| DEPLOY-AS-IS | 0 |
| NEEDS-REWRITE | 1,102 |
| **Total** | **1,102** |

| Detector Type | Count |
|---------------|-------|
| OCI_ACTIVITY | 1,099 |
| OCI_CONFIGURATION | 3 |
| OCI_THREAT | 0 |

## Important Notes

All 1,102 rules are marked as **NEEDS-REWRITE** because the original query format was generic SQL (`SELECT ... FROM oci_monitoring_metricexplorer_metrics WHERE ...`) which is not valid MQL. Each detector recipe has been generated with:

1. **Rewritten condition groups** — Cloud Guard native condition format using `fieldName`, `operator`, `value` patterns
2. **Original query preserved** in `dataSourceDetails.query` for reference
3. **Detector type auto-detected** — 1,099 activity (audit-based), 3 configuration-based
4. **Event name patterns extracted** from original SQL LIKE clauses where possible
5. **Default conditions** added where extraction wasn't possible

Before bulk deployment, test a few rules from each priority level to verify:
- Condition groups match your OCI audit log schema
- Detector type is correct for your Cloud Guard configuration
- Severity levels align with your incident response process