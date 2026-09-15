# OCI-WSTG04-016 — Session Fixation Attack

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_general_wstg04_016", "action" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'VcnFlowLogs' AND "action" = 'REJECT' AND "srcaddr" NOT LIKE '10.%' AND "dstaddr" NOT LIKE '10.%' AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-WSTG04-016_detector_recipe.json
