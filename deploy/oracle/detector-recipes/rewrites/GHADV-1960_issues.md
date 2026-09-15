# GHADV-1960 — http4k: `HmacSha256.hash` (despite the `Hmac` naming) computed a plain unkeyed digest; clarified by deprecation in favou

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_auth_bypass_ghadv_1960", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%http4k%' OR "data__json.message" LIKE '%hmacsha256%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-1960_detector_recipe.json
