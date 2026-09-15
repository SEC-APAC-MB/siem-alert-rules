resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-004" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-004: Lateral movement chain \u2014 WinRM \u2192 PS Remoting \u2192 Domain Controller"
  description     = "Detects WinRM-based lateral movement using PowerShell remoting to reach domain controllers"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-004_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "InstanceAction"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateWindowsInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateInstance"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-004"
      category      = "general"
      mitre_attack  = ["T1021.006", "T1059.001", "T1018"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "InstanceAction", "CreateWindowsInstance", "UpdateInstance"]
    }
  }
}
