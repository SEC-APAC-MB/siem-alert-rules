resource "oci_cloud_guard_detector_recipe" "ghadv-1817" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-1817: jackson-databind has @JsonView bypass for setterless creator properties"
  description     = "jackson-databind has @JsonView bypass for setterless creator properties"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-1817_conditions"
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
      rule_id       = "GHADV-1817"
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
