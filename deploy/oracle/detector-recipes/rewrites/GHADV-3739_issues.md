# GHADV-3739 — Spring AI: ChatMemory DEFAULT_CONVERSATION_ID causes unintended cross-user data leakage

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_CONFIGURATION

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_misconfiguration_ghadv_3739", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%spring%' OR "data__json.message" LIKE '%chatmemory%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-3739_detector_recipe.json
