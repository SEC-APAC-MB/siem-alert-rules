resource "oci_cloud_guard_detector_recipe" "oci-api-003" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-003: API3: Broken Object Property Level Authorization (BOPLA)"
  description     = "Detects API responses returning sensitive properties that the user should not access"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-003_conditions"
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
    value      = "CreateApiGateway"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateApiGateway"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-API-003"
      category      = "general"
      mitre_attack  = ["T1078"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "CreateApiGateway", "UpdateApiGateway"]
    }
  }
}
