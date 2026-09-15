# OCI-AI-DB-001 — AI — RAG Data Poisoning via Document Injection

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_general_ai_db_001", "data__json.rEventName" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'AuditEvents' AND "data__json.rEventName" LIKE '%rag%' AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-AI-DB-001_detector_recipe.json
