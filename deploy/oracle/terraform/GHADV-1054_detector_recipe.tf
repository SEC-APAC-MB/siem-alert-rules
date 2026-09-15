resource "oci_cloud_guard_detector_recipe" "ghadv-1054" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-1054: ArcadeDB: Trigger scripts run with java.lang.* allowed, enabling OS command execution (RCE)"
  description     = "ArcadeDB: Trigger scripts run with java.lang.* allowed, enabling OS command execution (RCE)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-1054_conditions"
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
    value      = "InvokeFunction"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateJobRun"
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
      }
    }

    labels = {
      rule_id       = "GHADV-1054"
      category      = "command-injection"
      mitre_attack  = ["T1059", "T1203"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["InstanceAction", "InvokeFunction", "CreateJobRun", "CreateInstance", "UpdateInstance"]
    }
  }
}
