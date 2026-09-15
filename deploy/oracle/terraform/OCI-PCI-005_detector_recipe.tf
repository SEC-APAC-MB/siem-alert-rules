resource "oci_cloud_guard_detector_recipe" "oci-pci-005" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-005: PCI-DSS \u2014 PAN Displayed in Cleartext"
  description     = "Detects primary account numbers displayed in cleartext violating PCI-DSS Requirement 3"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-005_conditions"
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
    value      = "UpdateUser"
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
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-005"
      category      = "general"
      mitre_attack  = ["T1530", "T1567"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateUser", "UpdateUser", "CreateOrResetUIPassword", "CreateApiKey", "CreateAuthToken"]
    }
  }
}
