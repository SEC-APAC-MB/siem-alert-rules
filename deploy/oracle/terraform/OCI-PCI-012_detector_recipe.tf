resource "oci_cloud_guard_detector_recipe" "oci-pci-012" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-012: PCI-DSS \u2014 Network Segmentation Violation in CDE"
  description     = "Detects traffic crossing network segmentation boundaries in cardholder data environment"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-012_conditions"
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
    value      = "CreateGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AddUserToGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdatePolicy"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-012"
      category      = "general"
      mitre_attack  = ["T1567", "T1021"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateUser", "CreateGroup", "AddUserToGroup", "CreatePolicy", "UpdatePolicy"]
    }
  }
}
