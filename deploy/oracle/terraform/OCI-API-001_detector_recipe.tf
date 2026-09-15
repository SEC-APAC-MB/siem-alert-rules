resource "oci_cloud_guard_detector_recipe" "oci-api-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-001: API1: Broken Object Level Authorization (BOLA)"
  description     = "Detects sequential or unauthorized access to API objects by ID indicating broken object-level authorization"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-001_conditions"
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
      rule_id       = "OCI-API-001"
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
