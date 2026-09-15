resource "oci_cloud_guard_detector_recipe" "oci-pci-016" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-016: PCI-DSS \u2014 Insecure Data Storage of PAN"
  description     = "Detects storage of unencrypted primary account numbers violating PCI-DSS Requirement 3"
  detector        = "OCI_CONFIGURATION"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-016_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventType"
    operator   = "IN"
    value      = "CreateBucket,UpdateBucket,CreateVolume,UpdateVolume"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-016"
      category      = "general"
      mitre_attack  = ["T1530", "T1567"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_CONFIGURATION"
      namespace   = "Compliance"
      events      = ["CreateBucket", "UpdateBucket", "CreateVolume", "UpdateVolume"]
    }
  }
}
