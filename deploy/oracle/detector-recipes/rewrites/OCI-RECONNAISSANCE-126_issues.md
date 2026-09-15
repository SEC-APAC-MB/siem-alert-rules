# OCI-RECONNAISSANCE-126 — Kubernetes API Server Recon

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_reconnaissance_reconnaissance_126", "action" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'VcnFlowLogs' AND "action" = 'REJECT' AND "dstport" IN (6443, 10250) AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-RECONNAISSANCE-126_detector_recipe.json
