resource "oci_cloud_guard_detector_recipe" "oci-auth-033" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AUTH-033: Authentication \u2014 PTH Over WinRM"
  description     = "Detects pass-the-hash attack patterns over WinRM connections"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AUTH-033_conditions"
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
      rule_id       = "OCI-AUTH-033"
      category      = "general"
      mitre_attack  = ["T1550.002", "T1021.006"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateOrResetUIPassword", "CreateAuthToken"]
    }
  }
}
