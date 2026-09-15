resource "oci_cloud_guard_detector_recipe" "ghadv-3083" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-3083: Jenkins Bitbucket OAuth Plugin does not restrict the redirect URL after login"
  description     = "Jenkins Bitbucket OAuth Plugin does not restrict the redirect URL after login"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-3083_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListInstances"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListObjects"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetAutonomousDatabase"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListAutonomousDbs"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-3083"
      category      = "redirect"
      mitre_attack  = ["T1200"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["GetInstance", "ListInstances", "GetObject", "ListObjects", "GetAutonomousDatabase", "ListAutonomousDbs"]
    }
  }
}
