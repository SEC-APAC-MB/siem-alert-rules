resource "oci_cloud_guard_detector_recipe" "oci-pci-014" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-014: PCI-DSS \u2014 Vulnerability Scanner Disabled in CDE"
  description     = "Detects disabling or misconfiguration of vulnerability scanning in cardholder data environment"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-014_conditions"
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
    value      = "DeleteUser"
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
      }
    }

    labels = {
      rule_id       = "OCI-PCI-014"
      category      = "general"
      mitre_attack  = ["T1562.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateUser", "DeleteUser", "UpdateUser", "CreateOrResetUIPassword"]
    }
  }
}
