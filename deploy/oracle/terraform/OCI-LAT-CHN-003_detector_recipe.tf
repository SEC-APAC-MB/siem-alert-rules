resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-003" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-003: Lateral movement chain \u2014 SSH \u2192 Privilege Escalation \u2192 Root Access"
  description     = "Detects SSH lateral movement followed by privilege escalation to root"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-003_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "InstanceAction"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePrivateIp"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-003"
      category      = "general"
      mitre_attack  = ["T1021.004", "T1548.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["InstanceAction", "CreateInstance", "UpdateInstance", "CreatePrivateIp"]
    }
  }
}
