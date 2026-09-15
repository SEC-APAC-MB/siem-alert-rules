resource "oci_cloud_guard_detector_recipe" "oci-api-012" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-012: API \u2014 GraphQL Query Depth Attack"
  description     = "Detects GraphQL queries with excessive depth or complexity indicating DoS or data extraction"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-012_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiDeployment"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateApiDeployment"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetApiDeployment"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-API-012"
      category      = "general"
      mitre_attack  = ["T1498"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "GetApiDeployment"]
    }
  }
}
