# OCI-API-005 — API5: Broken Function Level Authorization

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_general_api_005", "data__json.rEventName" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'AuditEvents' AND "data__json.rEventName" IN ('UpdateApiKey', 'UploadApiKey', 'CreateApiKey', 'DeleteApiKey') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-API-005_detector_recipe.json
