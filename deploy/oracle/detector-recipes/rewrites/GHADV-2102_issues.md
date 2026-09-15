# GHADV-2102 — NL Portal Backend Libraries: Document contents remained downloadable by any logged-in user (incomplete fix of CVE-2026-4

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_idor_ghadv_2102", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%portal%' OR "data__json.message" LIKE '%backend%') AND ("data__json.message" LIKE '%CVE-%' OR "data__json.message" LIKE '%exploit%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-2102_detector_recipe.json
