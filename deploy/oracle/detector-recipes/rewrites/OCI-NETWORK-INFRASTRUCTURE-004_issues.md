# OCI-NETWORK-INFRASTRUCTURE-004 — CVE-2026-20079 — Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management Exploitation

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_network_infrastructure_network_infrastructure_004", "data__json.message" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'OciLoggingService' AND ("data__json.message" LIKE '%cve%' OR "data__json.message" LIKE '%2026%') AND ("data__json.message" LIKE '%CVE-%' OR "data__json.message" LIKE '%exploit%') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/OCI-NETWORK-INFRASTRUCTURE-004_detector_recipe.json
