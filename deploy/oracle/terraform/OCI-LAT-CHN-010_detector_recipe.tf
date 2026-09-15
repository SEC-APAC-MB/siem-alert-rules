resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-010" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-010: Lateral movement chain \u2014 Supply Chain \u2192 Internal Pivot \u2192 Data Staging"
  description     = "Detects supply chain compromise followed by internal lateral movement and data staging for exfiltration"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-010_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "PutObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CopyObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateArchive"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateBackup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-010"
      category      = "general"
      mitre_attack  = ["T1195.002", "T1021", "T1560"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateObject", "PutObject", "CopyObject", "CreateArchive", "CreateBackup"]
    }
  }
}
