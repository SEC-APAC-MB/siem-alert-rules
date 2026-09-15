resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-025" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-025: Lateral movement chain \u2014 Supply Chain \u2192 Build Pipeline \u2192 Production Compromise"
  description     = "Detects supply chain compromise progressing through build pipeline to production environment"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-025_conditions"
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
    value      = "CreateCronJob"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-025"
      category      = "general"
      mitre_attack  = ["T1195.002", "T1053", "T1190"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateScheduledJob", "UpdateScheduledJob", "CreateCronJob"]
    }
  }
}
