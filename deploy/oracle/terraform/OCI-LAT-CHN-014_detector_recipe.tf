resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-014" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-014: Lateral movement chain \u2014 Service Account \u2192 Scheduled Task \u2192 Persistence"
  description     = "Detects service account compromise followed by scheduled task creation for persistence on multiple systems"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-014_conditions"
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
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-014"
      category      = "general"
      mitre_attack  = ["T1078.002", "T1053.005"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "Authenticate", "CreateAuthToken"]
    }
  }
}
