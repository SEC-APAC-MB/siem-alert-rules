resource "oci_cloud_guard_detector_recipe" "ghadv-4524" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-4524: Jenkins GitHub Plugin has an XSS vulnerability"
  description     = "Jenkins GitHub Plugin has an XSS vulnerability"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-4524_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiDeployment"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateApiDeployment"
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
    value      = "InvokeFunction"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-4524"
      category      = "xss"
      mitre_attack  = ["T1059.007"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "CreateInstance", "UpdateInstance", "InvokeFunction"]
    }
  }
}
