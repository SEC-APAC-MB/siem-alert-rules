resource "oci_cloud_guard_detector_recipe" "oci-wstg04-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG04-001: Credentials Transmitted Over Unencrypted Channel"
  description     = "Detects login or credential submission over HTTP instead of HTTPS exposing credentials to interception"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG04-001_conditions"
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
      rule_id       = "OCI-WSTG04-001"
      category      = "general"
      mitre_attack  = ["T1566"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateAuthToken", "CreateOrResetUIPassword"]
    }
  }
}
