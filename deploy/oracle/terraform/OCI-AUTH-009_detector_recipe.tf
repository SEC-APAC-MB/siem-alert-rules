resource "oci_cloud_guard_detector_recipe" "oci-auth-009" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AUTH-009: Authentication \u2014 Pass-the-Hash Detection"
  description     = "Detects NTLM authentication patterns consistent with pass-the-hash attacks"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AUTH-009_conditions"
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
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AUTH-009"
      category      = "general"
      mitre_attack  = ["T1550.002"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateOrResetUIPassword", "CreateAuthToken"]
    }
  }
}
