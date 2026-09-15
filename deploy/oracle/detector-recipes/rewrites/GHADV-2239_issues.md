# GHADV-2239 — Apache DolphinScheduler: Incorrect Authorization vulnerability allows users with system login privileges to delete task 

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_auth_bypass_ghadv_2239", "data__json.rEventName" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'AuditEvents' AND "data__json.rEventName" LIKE '%apache%' AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-2239_detector_recipe.json
