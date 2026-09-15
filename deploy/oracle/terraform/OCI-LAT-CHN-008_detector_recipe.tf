resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-008" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-008: Lateral movement chain \u2014 Kerberoasting \u2192 Ticket \u2192 Service Account"
  description     = "Detects Kerberoasting followed by TGS ticket usage to compromise service accounts"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-008_conditions"
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
    value      = "CreateDbCredential"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListAuthTokens"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-008"
      category      = "general"
      mitre_attack  = ["T1558.003", "T1550.003", "T1078.002"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateDbCredential", "GetAuthToken", "ListAuthTokens"]
    }
  }
}
