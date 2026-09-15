# GHADV-0076 — XWiki Platform Live Data Live Table Connector has privilege escalation from edit to script right through Live Data editi

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_auth_bypass_ghadv_0076", "data__json.rEventName" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'AuditEvents' AND "data__json.rEventName" LIKE '%xwiki%' AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-0076_detector_recipe.json
