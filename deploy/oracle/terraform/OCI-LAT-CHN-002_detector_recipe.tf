resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-002" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-002: Lateral movement chain \u2014 SMB \u2192 LSA Secrets \u2192 Domain Dominance"
  description     = "Detects SMB lateral movement progressing to LSA secret extraction and domain controller compromise"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-002_conditions"
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
    value      = "GetAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListApiKeys"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-002"
      category      = "general"
      mitre_attack  = ["T1021.002", "T1003.004", "T1558"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateApiKey", "GetAuthToken", "ListApiKeys"]
    }
  }
}
