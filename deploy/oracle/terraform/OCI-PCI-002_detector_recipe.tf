resource "oci_cloud_guard_detector_recipe" "oci-pci-002" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-002: PCI-DSS \u2014 Default Credentials in Cardholder Environment"
  description     = "Detects use of default vendor credentials in cardholder data environment violating PCI-DSS Requirement 8"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-002_conditions"
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
    value      = "CreateSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "EncryptData"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-002"
      category      = "general"
      mitre_attack  = ["T1078.001", "T1552.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVault", "CreateKey", "CreateSecret", "UpdateSecret", "EncryptData"]
    }
  }
}
