# GHADV-0144 — http4k: Unbounded gzip decompression in `ServerFilters.GZip` / `RequestFilters.GunZip` allowed memory-exhaustion DoS

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_other_ghadv_0144", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%http4k%' OR "data__json.message" LIKE '%unbounded%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-0144_detector_recipe.json
