resource "oci_cloud_guard_detector_recipe" "oci-api-014" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-014: API \u2014 Excessive Data Exposure in Response"
  description     = "Detects API responses returning more data than requested including PII, credentials, or internal fields"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-014_conditions"
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
      rule_id       = "OCI-API-014"
      category      = "general"
      mitre_attack  = ["T1213"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "GetApiDeployment", "ListApiDeployments"]
    }
  }
}
