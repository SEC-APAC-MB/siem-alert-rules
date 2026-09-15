resource "oci_cloud_guard_detector_recipe" "oci-execution-138" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-EXECUTION-138: WMI Remote Execution"
  description     = "Detect WMI-based remote command execution via wmiprvse"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-EXECUTION-138_conditions"
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
    value      = "CreateFunction"
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
      }
    }

    labels = {
      rule_id       = "OCI-EXECUTION-138"
      category      = "execution"
      mitre_attack  = []
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["InstanceAction", "CreateInstance", "UpdateInstance", "CreateFunction", "InvokeFunction", "CreateJobRun"]
    }
  }
}
