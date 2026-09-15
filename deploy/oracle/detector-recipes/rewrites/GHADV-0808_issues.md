# GHADV-0808 — Netty: [HttpContentEncoder] Unbounded Per-Connection Queue Growth via HTTP/1.1 Pipelining Leads to Denial of Service

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_dos_ghadv_0808", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%netty%' OR "data__json.message" LIKE '%httpcontentencoder%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-0808_detector_recipe.json
