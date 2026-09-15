# GHADV-1959 — http4k: BasicCookieStorage` (renamed `InsecureCookieStorage`) did not enforce RFC 6265 cookie scoping; new `DefaultCooki

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_info_disclosure_ghadv_1959", "data__json.rEventName" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'AuditEvents' AND "data__json.rEventName" IN ('PutObject', 'DeleteObject', 'CreateBucket', 'UpdateBucket', 'AbortMultipartUpload') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-1959_detector_recipe.json
