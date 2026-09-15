resource "oci_cloud_guard_detector_recipe" "oci-pci-011" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-011: PCI-DSS \u2014 Payment Skimming Detection"
  description     = "Detects web skimming or JavaScript injection targeting payment pages"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-011_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteVolumeBackup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteBootVolumeBackup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeletePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteVault"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-011"
      category      = "general"
      mitre_attack  = ["T1190", "T1059.007"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["DeleteVolumeBackup", "DeleteBootVolumeBackup", "DeletePolicy", "DeleteVault"]
    }
  }
}
