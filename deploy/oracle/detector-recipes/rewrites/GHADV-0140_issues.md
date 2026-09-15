# GHADV-0140 — http4k: `DigestAuthProvider.verify` ignored configured algorithm and did not bind to request URI

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_crypto_ghadv_0140", "action" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'VcnFlowLogs' AND "action" = 'REJECT' AND "dstport" IN (80, 443) AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-0140_detector_recipe.json
