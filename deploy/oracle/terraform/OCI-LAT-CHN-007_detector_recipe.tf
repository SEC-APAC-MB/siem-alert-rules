resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-007" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-007: Lateral movement chain \u2014 Pass-the-Hash \u2192 SMB \u2192 Domain Admin"
  description     = "Detects pass-the-hash attack followed by SMB lateral movement to gain domain admin privileges"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-007_conditions"
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
      rule_id       = "OCI-LAT-CHN-007"
      category      = "general"
      mitre_attack  = ["T1550.002", "T1021.002", "T1078.002"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateOrResetUIPassword", "CreateAuthToken"]
    }
  }
}
