resource "oci_cloud_guard_detector_recipe" "oci-wstg04-002" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG04-002: Default Credentials Usage on Login"
  description     = "Detects successful logins using common default usernames like admin, root, or test across services"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG04-002_conditions"
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
    value      = "AuthenticateUser"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-WSTG04-002"
      category      = "general"
      mitre_attack  = ["T1078.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "AuthenticateUser", "CreateApiKey"]
    }
  }
}
