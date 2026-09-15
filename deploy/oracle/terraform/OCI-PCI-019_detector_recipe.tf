resource "oci_cloud_guard_detector_recipe" "oci-pci-019" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-019: PCI-DSS \u2014 Third-Party Remote Access to CDE"
  description     = "Detects unauthorized third-party remote access to cardholder data environment"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-019_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSession"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-019"
      category      = "general"
      mitre_attack  = ["T1190", "T1133"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateAuthToken", "CreateApiKey", "CreateOrResetUIPassword"]
    }
  }
}
