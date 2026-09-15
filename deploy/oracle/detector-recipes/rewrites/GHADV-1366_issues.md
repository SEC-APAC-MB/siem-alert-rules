# GHADV-1366 — OpenRemote has an incomplete fix for CVE-2026-40882: XXE in KNXProtocol.startAssetImport() allows arbitrary file read vi

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_xxe_ghadv_1366", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%openremote%' OR "data__json.message" LIKE '%incomplete%') AND ("data__json.message" LIKE '%CVE-%' OR "data__json.message" LIKE '%exploit%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-1366_detector_recipe.json
