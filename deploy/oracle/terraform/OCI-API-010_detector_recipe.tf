resource "oci_cloud_guard_detector_recipe" "oci-api-010" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-010: API10: Unsafe Consumption of API Responses"
  description     = "Detects API responses containing executable content or unsafe data that could harm downstream systems"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-010_conditions"
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
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListApiDeployments"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-API-010"
      category      = "general"
      mitre_attack  = ["T1190"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "GetApiDeployment", "ListApiDeployments"]
    }
  }
}
