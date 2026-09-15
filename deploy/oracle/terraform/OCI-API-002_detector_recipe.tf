resource "oci_cloud_guard_detector_recipe" "oci-api-002" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-002: API2: Broken Authentication \u2014 Default Credentials"
  description     = "Detects API authentication attempts using default or well-known credentials"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-002_conditions"
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
      rule_id       = "OCI-API-002"
      category      = "general"
      mitre_attack  = ["T1078.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "GetApiDeployment", "ListApiDeployments"]
    }
  }
}
