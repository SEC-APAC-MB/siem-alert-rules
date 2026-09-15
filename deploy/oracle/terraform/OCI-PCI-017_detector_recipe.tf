resource "oci_cloud_guard_detector_recipe" "oci-pci-017" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-017: PCI-DSS \u2014 Malware Protection Disabled in CDE"
  description     = "Detects disabled or misconfigured malware protection in cardholder data environment"
  detector        = "OCI_CONFIGURATION"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-017_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventType"
    operator   = "IN"
    value      = "CreateVault,CreateKey,ScheduleKeyDeletion,DeleteKey,DisableKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-017"
      category      = "general"
      mitre_attack  = ["T1562.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_CONFIGURATION"
      namespace   = "Compliance"
      events      = ["CreateVault", "CreateKey", "ScheduleKeyDeletion", "DeleteKey", "DisableKey"]
    }
  }
}
