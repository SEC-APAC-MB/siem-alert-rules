resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-021" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-021: Lateral movement chain \u2014 Pass-the-Cert \u2192 AD CS \u2192 Domain Admin"
  description     = "Detects certificate-based authentication abuse followed by AD CS exploitation for domain admin"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-021_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSwiftPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-021"
      category      = "general"
      mitre_attack  = ["T1550.004", "T1558.004", "T1078.002"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateApiKey", "CreateOrResetUIPassword", "CreateSwiftPassword"]
    }
  }
}
