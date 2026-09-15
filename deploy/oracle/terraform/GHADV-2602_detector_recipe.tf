resource "oci_cloud_guard_detector_recipe" "ghadv-2602" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-2602: Jenkins: Missing permission check allows unauthorized cancellation of queue items"
  description     = "Jenkins: Missing permission check allows unauthorized cancellation of queue items"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-2602_conditions"
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
      rule_id       = "GHADV-2602"
      category      = "auth-bypass"
      mitre_attack  = ["T1548"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdatePolicy", "CreatePolicy", "AddUserToGroup", "UpdateUserCapabilities"]
    }
  }
}
