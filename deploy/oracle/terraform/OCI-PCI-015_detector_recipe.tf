resource "oci_cloud_guard_detector_recipe" "oci-pci-015" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-015: PCI-DSS \u2014 Expired SSL/TLS Certificate in CDE"
  description     = "Detects expired or expiring SSL/TLS certificates in cardholder data environment"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-015_conditions"
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
      rule_id       = "OCI-PCI-015"
      category      = "general"
      mitre_attack  = ["T1552.004"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateAutonomousDatabase", "ChangeAutonomousDatabaseAdminPassword", "RotateAutonomousDatabaseEncryptionKey"]
    }
  }
}
