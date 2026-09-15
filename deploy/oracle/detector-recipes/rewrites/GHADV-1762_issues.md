# GHADV-1762 — nextflow auth login command has incorrect default permissions

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_CONFIGURATION

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_misconfiguration_ghadv_1762", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%nextflow%' OR "data__json.message" LIKE '%auth%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-1762_detector_recipe.json
