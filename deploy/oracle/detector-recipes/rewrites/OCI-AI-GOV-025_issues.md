# OCI-AI-GOV-025 — AI — Unauthorized Data Processing Purpose

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_general_ai_gov_025", "metricName" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'oci_objectstorage' AND "metricName" = 'StorageSizeBytes' AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-AI-GOV-025_detector_recipe.json
