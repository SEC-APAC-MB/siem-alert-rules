resource "oci_cloud_guard_detector_recipe" "oci-pci-006" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-006: PCI-DSS \u2014 Weak Cryptography in CDE"
  description     = "Detects use of weak or deprecated cryptographic algorithms in cardholder data environment"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-006_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateAutonomousDatabase"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ChangeAutonomousDatabaseAdminPassword"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "RotateAutonomousDatabaseEncryptionKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-006"
      category      = "general"
      mitre_attack  = ["T1552.001", "T1110"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateAutonomousDatabase", "ChangeAutonomousDatabaseAdminPassword", "RotateAutonomousDatabaseEncryptionKey"]
    }
  }
}
