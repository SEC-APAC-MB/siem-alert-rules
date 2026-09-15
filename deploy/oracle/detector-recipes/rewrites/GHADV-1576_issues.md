# GHADV-1576 — GeoNetwork has ACL bypass on Elasticsearch search when request body omits query field

**Status:** NEEDS-REWRITE

**Detector Type:** OCI_ACTIVITY

**Issues:**
- Query is generic SQL, needs conversion to Cloud Guard detector condition

**Original Query:**
```
SELECT "siem_auth_bypass_ghadv_1576", "data__json.rEventName" FROM "oci_monitoring_metricexplorer_metrics" WHERE "compartmentId" = '$COMPARTMENT_ID' AND "namespace" = 'AuditEvents' AND "data__json.rEventName" IN ('CreateVcn', 'UpdateVcn', 'DeleteVcn', 'CreateSubnet', 'UpdateSubnet', 'DeleteSubnet', 'CreateSecurityList', 'UpdateSecurityList', 'CreateNetworkSecurityGroup', 'UpdateNetworkSecurityGroup') AND "value" > 0
```

**Recipe file (with rewrite):** /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes/GHADV-1576_detector_recipe.json
