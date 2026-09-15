resource "oci_cloud_guard_detector_recipe" "oci-pci-024" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-024: PCI-DSS \u2014 Data Retention Violation in CDE"
  description     = "Detects cardholder data retained beyond required periods or not destroyed properly"
  detector        = "OCI_CONFIGURATION"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-024_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventType"
    operator   = "IN"
    value      = "UpdateAutonomousDatabase,RotateAutonomousDatabaseEncryptionKey,ChangeAutonomousDatabaseAdminPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-024"
      category      = "general"
      mitre_attack  = ["T1530"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_CONFIGURATION"
      namespace   = "Compliance"
      events      = ["UpdateAutonomousDatabase", "RotateAutonomousDatabaseEncryptionKey", "ChangeAutonomousDatabaseAdminPassword"]
    }
  }
}
