resource "oci_cloud_guard_detector_recipe" "oci-pci-020" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-020: PCI-DSS \u2014 Change Control Violation in CDE"
  description     = "Detects unauthorized changes to cardholder data environment without proper change control"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-020_conditions"
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
    value      = "GetSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ScheduleSecretDeletion"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-020"
      category      = "general"
      mitre_attack  = ["T1195.002", "T1562"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVault", "CreateSecret", "UpdateSecret", "GetSecret", "ScheduleSecretDeletion"]
    }
  }
}
