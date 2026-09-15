resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-017" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-017: Lateral movement chain \u2014 Email \u2192 Macro \u2192 PowerShell \u2192 Exfiltration"
  description     = "Detects email-delivered macro followed by PowerShell execution and data exfiltration"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-017_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSession"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-017"
      category      = "general"
      mitre_attack  = ["T1566.001", "T1059.001", "T1566"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateAuthToken", "CreateOrResetUIPassword"]
    }
  }
}
