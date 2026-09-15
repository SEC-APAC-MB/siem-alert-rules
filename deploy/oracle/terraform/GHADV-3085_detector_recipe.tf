resource "oci_cloud_guard_detector_recipe" "ghadv-3085" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-3085: Jenkins GitHub Integration Plugin has a cross-site request forgery (CSRF) vulnerability"
  description     = "Jenkins GitHub Integration Plugin has a cross-site request forgery (CSRF) vulnerability"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-3085_conditions"
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
    value      = "CreatePrivateIp"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVnic"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecurityRule"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateNetworkSecurityGroup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-3085"
      category      = "csrf"
      mitre_attack  = ["T1534"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "CreatePrivateIp", "CreateVnic", "UpdateSecurityRule", "CreateNetworkSecurityGroup"]
    }
  }
}
