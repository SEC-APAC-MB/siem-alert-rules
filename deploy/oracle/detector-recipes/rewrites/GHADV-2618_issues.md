# GHADV-2618 — Spring for Apache Pulsar: JsonPulsarHeaderMapper Trusted-Package Prefix Check Allows Unintended Subpackage Deserializati

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_deserialization_ghadv_2618", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%spring%' OR "data__json.message" LIKE '%apache%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-2618_detector_recipe.json
