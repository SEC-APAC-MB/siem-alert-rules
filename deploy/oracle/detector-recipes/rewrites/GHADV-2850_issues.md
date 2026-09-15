# GHADV-2850 — Apache MINA: Critical Deserialization Allow-list Bypass via resolveProxyClass

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_deserialization_ghadv_2850", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%apache%' OR "data__json.message" LIKE '%mina%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-2850_detector_recipe.json
