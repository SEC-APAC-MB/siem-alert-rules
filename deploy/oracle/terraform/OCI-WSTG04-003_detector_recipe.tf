resource "oci_cloud_guard_detector_recipe" "oci-wstg04-003" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG04-003: Account Lockout Mechanism Failure"
  description     = "Detects more than 20 failed login attempts for a single account without lockout indicating weak lockout policy"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG04-003_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-WSTG04-003"
      category      = "general"
      mitre_attack  = ["T1110.003"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateApiKey", "CreateOrResetUIPassword"]
    }
  }
}
