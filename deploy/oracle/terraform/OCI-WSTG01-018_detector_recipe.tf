resource "oci_cloud_guard_detector_recipe" "oci-wstg01-018" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG01-018: Account Provisioning Without Approval"
  description     = "Detects account creation events bypassing approval workflows"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG01-018_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateUser"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateDbUser"
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
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-WSTG01-018"
      category      = "general"
      mitre_attack  = ["T1136"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateUser", "CreateDbUser", "CreateDbCredential", "CreateApiKey"]
    }
  }
}
