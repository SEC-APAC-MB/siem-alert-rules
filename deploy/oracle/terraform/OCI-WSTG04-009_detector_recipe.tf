resource "oci_cloud_guard_detector_recipe" "oci-wstg04-009" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG04-009: Credential Stuffing Attack Detected"
  description     = "Detects credential stuffing patterns with high volume login failures from the same source across multiple accounts"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG04-009_conditions"
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
      }
    }

    labels = {
      rule_id       = "OCI-WSTG04-009"
      category      = "general"
      mitre_attack  = ["T1110.004"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateApiKey", "CreateOrResetUIPassword"]
    }
  }
}
