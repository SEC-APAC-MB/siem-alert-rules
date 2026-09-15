resource "oci_cloud_guard_detector_recipe" "oci-pci-003" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-003: PCI-DSS \u2014 Unauthorized Access to Cardholder Data"
  description     = "Detects unauthorized access attempts to cardholder data stores violating PCI-DSS Requirement 7"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-003_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteLog"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateLog"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteLogGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteAuditEvent"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-003"
      category      = "general"
      mitre_attack  = ["T1552", "T1530"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["DeleteLog", "UpdateLog", "DeleteLogGroup", "DeleteAuditEvent"]
    }
  }
}
