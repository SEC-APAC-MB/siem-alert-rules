resource "oci_cloud_guard_detector_recipe" "oci-wstg04-005" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG04-005: Weak Remember-Me Cookie Detection"
  description     = "Detects authentication cookies lacking proper security attributes or containing predictable values"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG04-005_conditions"
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
      rule_id       = "OCI-WSTG04-005"
      category      = "general"
      mitre_attack  = ["T1539"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "Authenticate", "CreateAuthToken", "ListApiKeys"]
    }
  }
}
