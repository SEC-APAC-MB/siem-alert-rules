resource "oci_cloud_guard_detector_recipe" "oci-pci-008" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-008: PCI-DSS \u2014 Excessive Privileges in CDE"
  description     = "Detects users with excessive privileges in cardholder data environment violating least privilege"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-008_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AddUserToGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "RemoveUserFromGroup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-008"
      category      = "general"
      mitre_attack  = ["T1548", "T1078.002"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdatePolicy", "CreatePolicy", "AddUserToGroup", "RemoveUserFromGroup"]
    }
  }
}
