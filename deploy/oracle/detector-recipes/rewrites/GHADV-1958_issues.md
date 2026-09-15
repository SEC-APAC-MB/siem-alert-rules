# GHADV-1958 — http4k: `ServerFilters.DigestAuth` / `DigestAuthProvider` defaulted to an always-true nonce verifier, disabling replay p

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_auth_bypass_ghadv_1958", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%http4k%' OR "data__json.message" LIKE '%serverfilters%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-1958_detector_recipe.json
