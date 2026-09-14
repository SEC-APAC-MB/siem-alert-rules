# DORA Deployment Package — EU Digital Operational Resilience Act

SIEM alert rules mapped to the **EU Regulation (EU) 2022/2554 (DORA)** for
production deployment to **Oracle Cloud Infrastructure (OCI)** and
**Microsoft Azure Sentinel**.

This package is generated from `mappings/dora-mappings.json` and bundles the
referenced SIEM rules for **OCI** (`rules/oracle/*.json`) and **Azure**
(`rules/azure/*.json`).

## Contents

```
deployments/dora/
├── README.md                    # This file
├── deployment-config.yaml       # Environment configuration template
├── compliance-matrix.json       # Article → rule mapping
├── oracle/
│   ├── rules.json               # 23 DORA-mapped Oracle rules
│   └── deploy.sh                # OCI CLI deployment script
└── azure/
    ├── rules.json               # 23 DORA-mapped Azure Sentinel rules
    ├── deploy.sh                # Azure CLI deployment script (Bash)
    └── deploy.ps1               # Azure CLI deployment script (PowerShell)
```

## DORA Context

DORA harmonises ICT risk management for the EU financial sector. Its ICT Risk
Management Framework (Art. 5–9) requires financial entities to identify,
protect-and-prevent, detect, respond-and-recover, and continuously test their
ICT systems. Art. 10 defines incident reporting; Art. 28 covers third-party
ICT risk; Art. 44 penalties. The SIEM rules in this package operationalise
**detection** — the "D" of DORA's ICT risk management framework — as
continuous security monitoring of cloud workloads.

Covered articles:

| Article | Title | Control areas |
|---|---|---|
| Art. 5 | ICT Risk Management Framework | Risk identification, protection and prevention, detection, response and recovery, learning and communication |
| Art. 6 | ICT Systems and Tools | System integrity, availability, data protection, access control |
| Art. 7 | Protection and Prevention | Vulnerability management, patch management, network security, encryption |
| Art. 8 | Detection | Anomaly detection, incident alerting, continuous monitoring |
| Art. 9 | ICT-Related Incident Management | Incident classification, response procedures, escalation |
| Art. 10 | Incident Reporting | Initial notification (4 h), intermediate report (72 h), final report (1 month) |
| Art. 11 | Digital Operational Resilience Testing | Vulnerability assessment, penetration testing, TLPT, ICT risk scenario testing |
| Art. 28 | Third-Party ICT Risk | Supply chain risk assessment, contractual provisions, monitoring and oversight |
| Art. 44 | Penalties | Administrative fines up to 1% daily turnover, penalties up to 5M EUR |

**Coverage note:** the 35 DORA rule mappings in `mappings/dora-mappings.json`
currently resolve to **Art. 5–10 and Art. 28** controls; the remaining declared
articles (Art. 11 testing, Art. 44 penalties) are addressed through those
controls and listed here for the audit trail. `compliance-matrix.json` records
which rule IDs cover each control. Mappings whose rule IDs are not (yet)
exported for OCI/Azure are listed under `unresolved_mappings`.

## What is deployed

- **Oracle (23 rules):** OCI Monitoring Alarms with production-grade MQL queries
  against `oci_monitoring_metricexplorer_metrics` (sources: `AuditEvents`,
  `VcnFlowLogs`, `OciLoggingService`, `oci_database`, `oci_objectstorage`,
  `oci_computeagent`, `oci_lbaas`). Audit-based rules additionally get an
  OCI Events rule. `$COMPARTMENT_ID` is substituted from the environment /
  config at deploy time.
- **Azure Sentinel (23 rules):** Scheduled analytics rules with real KQL
  (`SigninLogs`, `AuditLogs`, `SecurityEvent`, `CommonSecurityLog`,
  `AzureDiagnostics`, …), valid Sentinel `tactics`, and tuned
  `queryFrequency` / `queryPeriod` / `triggerThreshold`.

Each rule keeps its original `rule_id`, `name`, `description`, `severity` and
`compliance` tags.

## Prerequisites

### OCI (`oracle/deploy.sh`)
1. OCI CLI installed and configured (`oci --version`).
2. Authenticated session (API key config or instance principal) with IAM
   policy allowing `manage alarms` / `manage events-rules` in the target
   compartment.
3. A pre-created ONS notification topic (email / pager) —
   `oci ons topic create`.
4. The target compartment OCID.

### Azure Sentinel (`azure/deploy.sh` / `azure/deploy.ps1`)
1. Azure CLI installed and `az login` completed (or service principal).
2. `sentinel` CLI extension: `az extension add --name sentinel`.
3. A Log Analytics workspace with Microsoft Sentinel enabled.
4. Subscription ID, resource group and workspace name.

## Deploying

```bash
# 1. Configure your environment
cp deployment-config.yaml my-dora-config.yaml
# 2. Edit my-dora-config.yaml

# Oracle
cd oracle
./deploy.sh --config ../my-dora-config.yaml

# Azure (Bash)
cd azure && ./deploy.sh --config ../my-dora-config.yaml

# Azure (PowerShell)
cd azure && ./deploy.ps1 -Config ..\my-dora-config.yaml
```

### Useful flags (all scripts)

| Flag | Effect |
|---|---|
| `--dry-run` | Validate CLI, auth and every rule — no resources created |
| `--compliance DORA` | Deploy only rules tagged for that regulation (NIS2/DORA/ALL) |
| `--config <file>` | Read environment parameters from a YAML config |

Each script validates prerequisites and reports per-rule success/failure with
`rule_id`, prints a summary (`success` / `failed` / `skipped`), and exits
non-zero if any rule failed to deploy.

## Verifying deployment

```bash
# OCI
oci monitoring alarm list --compartment-id "$OCI_COMPARTMENT_ID"

# Azure
az sentinel alert-rule list --resource-group "$AZ_RESOURCE_GROUP" --workspace-name "$AZ_WORKSPACE_NAME"
```

## Rollback

```bash
# OCI
oci monitoring alarm delete --alarm-id ocid1.alarm.oc1..xxxx

# Azure
az sentinel alert-rule delete --resource-group "$AZ_RESOURCE_GROUP" \
    --workspace-name "$AZ_WORKSPACE_NAME" --name <rule_id>
```

## Regenerating this package

```bash
python3 scripts/build_deployment_packages.py
```

## Support

- Rule semantics: see root `SECURITY_RULES.md`
- Contribution guide: see `docs/contributing.md`