# GHADV-0807 — Netty: [codec-http2] Lack of Host Header Deduplication in HTTP/2→HTTP/1.x Translation Leads to Request Routing Bypass

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_request_smuggling_ghadv_0807", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%netty%' OR "data__json.message" LIKE '%codec%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-0807_detector_recipe.json
