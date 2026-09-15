# GHADV-1053 — ArcadeDB: Scripting authorization gate (GHSA-48qw-824m-86pr) bypassed via SQL DEFINE FUNCTION ... LANGUAGE js

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_injection_ghadv_1053", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%arcadedb%' OR "data__json.message" LIKE '%scripting%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-1053_detector_recipe.json
