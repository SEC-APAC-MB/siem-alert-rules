resource "oci_cloud_guard_detector_recipe" "oci-pci-023" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-023: PCI-DSS \u2014 Insecure Password Policy in CDE"
  description     = "Detects accounts in cardholder data environment with password policies not meeting PCI-DSS requirements"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-023_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateBootVolumeBackup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVolumeBackup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateBootVolumeBackup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateVolumeBackup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-023"
      category      = "general"
      mitre_attack  = ["T1110"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateBootVolumeBackup", "CreateVolumeBackup", "UpdateBootVolumeBackup", "UpdateVolumeBackup"]
    }
  }
}
