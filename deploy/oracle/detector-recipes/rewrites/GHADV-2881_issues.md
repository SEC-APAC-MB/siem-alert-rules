# GHADV-2881 — Apache ActiveMQ has an Incorrect Default Permissions vulnerability

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_CONFIGURATION

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_misconfiguration_ghadv_2881", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%apache%' OR "data__json.message" LIKE '%activemq%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-2881_detector_recipe.json
