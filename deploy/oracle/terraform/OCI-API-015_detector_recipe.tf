resource "oci_cloud_guard_detector_recipe" "oci-api-015" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-015: API \u2014 NoSQL Injection in Request Parameters"
  description     = "Detects NoSQL injection operators ($where, $regex, $gt) in API request parameters"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-015_conditions"
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
      rule_id       = "OCI-API-015"
      category      = "general"
      mitre_attack  = ["T1190"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "CreateApiGateway", "UpdateApiGateway"]
    }
  }
}
