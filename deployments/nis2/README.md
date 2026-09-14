# NIS2 Deployment Package — EU NIS2 Directive

SIEM alert rules mapped to the **EU Directive (EU) 2022/2555 (NIS2)** for
production deployment to **Oracle Cloud Infrastructure (OCI)** and
**Microsoft Azure Sentinel**.

This package is generated from `mappings/nis2-mappings.json` and bundles the
referenced SIEM rules for **OCI** (`rules/oracle/*.json`) and **Azure**
(`rules/azure/*.json`).

## Contents

```
deployments/nis2/
├── README.md                    # This file
├── deployment-config.yaml       # Environment configuration template
├── compliance-matrix.json       # Article → rule mapping
├── oracle/
│   ├── rules.json               # 25 NIS2-mapped Oracle rules
│   └── deploy.sh                # OCI CLI deployment script
└── azure/
    ├── rules.json               # 25 NIS2-mapped Azure Sentinel rules
    ├── deploy.sh                # Azure CLI deployment script (Bash)
    └── deploy.ps1               # Azure CLI deployment script (PowerShell)
```

## NIS2 Context

The NIS2 Directive is the EU-wide legislation on cybersecurity for essential
and important entities (Art. 5). Its core security measures (Art. 15) require
risk analysis, information-system security, incident handling, business
continuity, supply-chain security and staff training; Art. 16 lays down
reporting obligations (early warning 24 h, notification 72 h, final report
1 month). The SIEM rules in this package operationalise the **detection** side
of those obligations as continuous security monitoring of cloud workloads.

Covered articles:

| Article | Title | Control areas |
|---|---|---|
| Art. 5 | Scope – Essential and Important Entities | Risk management, incident reporting, supply chain security |
| Art. 7 | Cooperation Group | Information sharing, best practices, vulnerability disclosure |
| Art. 14 | Personal Data Processing | Data protection by design, data minimization, encryption |
| Art. 15 | Risk Management Measures | Risk analysis, information system security, incident handling, business continuity, supply chain security, training |
| Art. 16 | Reporting Obligations | Early warning (24 h), incident notification (72 h), final report (1 month) |
| Art. 17 | Registration | Entity registration, contact point |
| Art. 21 | Supervision and Enforcement | Audit rights, penalties, remedies |
| Art. 30 | Penalties | Administrative fines up to 10M EUR or 2% global turnover |

**Coverage note:** the 37 NIS2 rule mappings in `mappings/nis2-mappings.json`
currently resolve to **Art. 15 and Art. 16** controls; the remaining declared
articles are addressed through those controls and are listed here for the
audit trail. `compliance-matrix.json` records which rule IDs cover each
control. Mappings whose rule IDs are not (yet) exported for OCI/Azure are
listed under `unresolved_mappings` in `compliance-matrix.json`.

## What is deployed

- **Oracle (25 rules):** OCI Monitoring Alarms with production-grade MQL queries
  against `oci_monitoring_metricexplorer_metrics` (sources: `AuditEvents`,
  `VcnFlowLogs`, `OciLoggingService`, `oci_database`, `oci_objectstorage`,
  `oci_computeagent`, `oci_lbaas`). Audit-based rules additionally get an
  OCI Events rule. `$COMPARTMENT_ID` is substituted from the environment /
  config at deploy time.
- **Azure Sentinel (25 rules):** Scheduled analytics rules with real KQL
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
3. A pre-created ONS notification topic (email / pager) for alerts —
   `oci ons topic create`.
4. The target compartment OCID.

ProTip: `export OCI_COMPARTMENT_ID=ocid1.compartment.oc1..xxxx`

### Azure Sentinel (`azure/deploy.sh` / `azure/deploy.ps1`)
1. Azure CLI installed and `az login` completed (or service principal).
2. `sentinel` CLI extension: `az extension add --name sentinel`.
3. A Log Analytics workspace with Microsoft Sentinel enabled.
4. Subscription ID, resource group and workspace name.

## Deploying

```bash
# 1. Configure your environment
cp deployment-config.yaml my-nis2-config.yaml
# 2. Edit my-nis2-config.yaml

# Oracle
cd oracle
./deploy.sh --config ../my-nis2-config.yaml        # real deployment
# or export OCI_COMPARTMENT_ID and ONS_TOPIC_ID and run:
./deploy.sh

# Azure (Bash)
cd azure && ./deploy.sh --config ../my-nis2-config.yaml

# Azure (PowerShell)
cd azure && ./deploy.ps1 -Config ..\my-nis2-config.yaml
```

### Useful flags (all scripts)

| Flag | Effect |
|---|---|
| `--dry-run` | Validate CLI, auth and every rule — no resources created |
| `--compliance NIS2` | Deploy only rules tagged for that regulation (NIS2/DORA/ALL) |
| `--config <file>` | Read environment parameters from a YAML config |

Each script:
- validates prerequisites and reports per-rule success/failure with `rule_id`;
- prints a summary (`success` / `failed` / `skipped`);
- exits non-zero if any rule failed to deploy.

## Verifying deployment

```bash
# OCI
oci monitoring alarm list --compartment-id "$OCI_COMPARTMENT_ID"
oci events rule list --compartment-id "$OCI_COMPARTMENT_ID"

# Azure
az sentinel alert-rule list --resource-group "$AZ_RESOURCE_GROUP" --workspace-name "$AZ_WORKSPACE_NAME"
```

## Rollback

```bash
# OCI: delete a single alarm (repeat per rule_id)
oci monitoring alarm delete --alarm-id ocid1.alarm.oc1..xxxx

# Azure: delete a single analytics rule
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