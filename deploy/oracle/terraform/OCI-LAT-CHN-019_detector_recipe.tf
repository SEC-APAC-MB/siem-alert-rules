resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-019" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-019: Lateral movement chain \u2014 Container Escape \u2192 Cloud Metadata \u2192 IAM Abuse"
  description     = "Detects container escape followed by cloud metadata service access and IAM privilege escalation"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-019_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AddUserToGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateUserCapabilities"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-019"
      category      = "general"
      mitre_attack  = ["T1611", "T1552.005", "T1548"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdatePolicy", "CreatePolicy", "AddUserToGroup", "UpdateUserCapabilities"]
    }
  }
}
