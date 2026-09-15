resource "oci_cloud_guard_detector_recipe" "oci-wstg04-007" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG04-007: Weak Authentication \u2014 Basic Auth Over HTTP"
  description     = "Detects HTTP Basic Authentication over unencrypted connections exposing credentials in cleartext"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG04-007_conditions"
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
      rule_id       = "OCI-WSTG04-007"
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
