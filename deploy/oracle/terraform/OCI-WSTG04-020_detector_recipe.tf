resource "oci_cloud_guard_detector_recipe" "oci-wstg04-020" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG04-020: Insecure Session Cookie Attributes"
  description     = "Detects session cookies missing Secure, HttpOnly, or SameSite attributes"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG04-020_conditions"
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
    value      = "Authenticate"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListApiKeys"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-WSTG04-020"
      category      = "general"
      mitre_attack  = ["T1539", "T1187"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "Authenticate", "CreateAuthToken", "ListApiKeys"]
    }
  }
}
