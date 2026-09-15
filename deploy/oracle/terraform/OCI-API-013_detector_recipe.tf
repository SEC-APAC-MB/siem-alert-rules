resource "oci_cloud_guard_detector_recipe" "oci-api-013" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-013: API \u2014 JWT Token None Algorithm Attack"
  description     = "Detects JWT tokens with algorithm set to none or missing algorithm indicating authentication bypass"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-013_conditions"
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
      rule_id       = "OCI-API-013"
      category      = "general"
      mitre_attack  = ["T1606"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "CreateApiGateway", "UpdateApiGateway"]
    }
  }
}
