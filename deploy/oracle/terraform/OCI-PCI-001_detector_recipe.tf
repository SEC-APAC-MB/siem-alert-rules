resource "oci_cloud_guard_detector_recipe" "oci-pci-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-001: PCI-DSS \u2014 Unencrypted Cardholder Data Transmission"
  description     = "Detects transmission of cardholder data over unencrypted channels violating PCI-DSS Requirement 4"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-001_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateBucket"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateBucket"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateVolume"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVolume"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-001"
      category      = "general"
      mitre_attack  = ["T1040", "T1567"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateBucket", "CreateBucket", "UpdateVolume", "CreateVolume"]
    }
  }
}
