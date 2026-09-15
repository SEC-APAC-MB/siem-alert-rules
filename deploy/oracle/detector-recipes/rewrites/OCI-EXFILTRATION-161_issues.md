# OCI-EXFILTRATION-161 — Email Data Exfiltration

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_exfiltration_exfiltration_161", "action" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'VcnFlowLogs' AND "action" = 'REJECT' AND "dstport" IN (25, 465, 587) AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-EXFILTRATION-161_detector_recipe.json
