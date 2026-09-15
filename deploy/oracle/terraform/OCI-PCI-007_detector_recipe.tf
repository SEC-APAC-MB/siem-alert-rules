resource "oci_cloud_guard_detector_recipe" "oci-pci-007" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-007: PCI-DSS \u2014 Wireless Access Point in CDE"
  description     = "Detects unauthorized wireless access points in or near cardholder data environment"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-007_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateBootVolume"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateBootVolume"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-007"
      category      = "general"
      mitre_attack  = ["T1190", "T1133"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "UpdateInstance", "CreateBootVolume", "UpdateBootVolume"]
    }
  }
}
