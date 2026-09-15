# OCI-LAT-CHN-024 — Lateral movement chain — Cloud Storage → Key Theft → Subscription Takeover

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_general_lat_chn_024", "metricName" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'oci_objectstorage' AND "metricName" = 'StorageSizeBytes' AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-LAT-CHN-024_detector_recipe.json
