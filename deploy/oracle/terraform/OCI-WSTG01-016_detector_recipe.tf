resource "oci_cloud_guard_detector_recipe" "oci-wstg01-016" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG01-016: Default Credentials on Network Devices"
  description     = "Detects login attempts using default credentials on network devices, firewalls, and routers"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG01-016_conditions"
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
      rule_id       = "OCI-WSTG01-016"
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
