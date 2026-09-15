resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-005" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-005: Lateral movement chain \u2014 WMI \u2192 Scheduled Task \u2192 Persistence"
  description     = "Detects WMI-based lateral movement creating scheduled tasks for persistence across multiple hosts"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-005_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateScheduledJob"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateScheduledJob"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateJob"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateJob"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-005"
      category      = "general"
      mitre_attack  = ["T1047", "T1053.005", "T1059"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateScheduledJob", "UpdateScheduledJob", "CreateJob", "UpdateJob"]
    }
  }
}
