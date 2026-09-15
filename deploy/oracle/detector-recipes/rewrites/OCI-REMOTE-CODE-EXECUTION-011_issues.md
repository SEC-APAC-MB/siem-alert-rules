# OCI-REMOTE-CODE-EXECUTION-011 — CVE-2026-85046 — Chromium V8 Exploitation

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_remote_code_execution_remote_code_execution_011", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%cve%' OR "data__json.message" LIKE '%2026%') AND ("data__json.message" LIKE '%CVE-%' OR "data__json.message" LIKE '%exploit%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-REMOTE-CODE-EXECUTION-011_detector_recipe.json
