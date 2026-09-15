resource "oci_cloud_guard_detector_recipe" "ghadv-3966" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-3966: Alkacon OpenCms is vulnerable to XSS via updateModelGroups.jsp"
  description     = "Alkacon OpenCms is vulnerable to XSS via updateModelGroups.jsp"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-3966_conditions"
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
      rule_id       = "GHADV-3966"
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
