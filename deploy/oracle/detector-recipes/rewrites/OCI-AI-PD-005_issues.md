# OCI-AI-PD-005 — AI — Data Exfiltration via Model Output

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_general_ai_pd_005", "action" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'VcnFlowLogs' AND "action" = 'REJECT' AND "srcaddr" NOT LIKE '10.%' AND "dstaddr" NOT LIKE '10.%' AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-AI-PD-005_detector_recipe.json
