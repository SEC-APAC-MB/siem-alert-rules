resource "oci_cloud_guard_detector_recipe" "oci-auth-007" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AUTH-007: Authentication \u2014 Default Credential Usage"
  description     = "Detects login attempts using known default credentials on systems or devices"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AUTH-007_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSession"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AuthenticateUser"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AUTH-007"
      category      = "general"
      mitre_attack  = ["T1078.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "AuthenticateUser", "CreateApiKey"]
    }
  }
}
