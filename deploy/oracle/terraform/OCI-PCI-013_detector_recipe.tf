resource "oci_cloud_guard_detector_recipe" "oci-pci-013" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-013: PCI-DSS \u2014 Physical Access to CDE Without Badge"
  description     = "Detects physical access to cardholder data environment without proper badge or authorization"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-013_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVault"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ScheduleKeyDeletion"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DisableKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-013"
      category      = "general"
      mitre_attack  = ["T1566.002"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVault", "CreateKey", "ScheduleKeyDeletion", "DisableKey", "DeleteKey"]
    }
  }
}
