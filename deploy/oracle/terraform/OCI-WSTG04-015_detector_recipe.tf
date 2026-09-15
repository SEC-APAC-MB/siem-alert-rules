resource "oci_cloud_guard_detector_recipe" "oci-wstg04-015" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG04-015: Cross-Site Request Forgery (CSRF)"
  description     = "Detects POST/PUT/DELETE requests missing CSRF tokens indicating potential cross-site request forgery"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG04-015_conditions"
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
    value      = "InstanceAction"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecurityRule"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-WSTG04-015"
      category      = "general"
      mitre_attack  = ["T1189"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "CreatePrivateIp", "CreateVnic", "InstanceAction", "UpdateSecurityRule"]
    }
  }
}
