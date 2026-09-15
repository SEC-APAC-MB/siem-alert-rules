resource "oci_cloud_guard_detector_recipe" "oci-pci-010" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-010: PCI-DSS \u2014 SQL Injection Against Payment System"
  description     = "Detects SQL injection attacks targeting payment processing systems"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-010_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateNetworkSecurityGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecurityList"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecurityRule"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteSecurityRule"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PCI-010"
      category      = "general"
      mitre_attack  = ["T1190", "T1059"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateNetworkSecurityGroup", "UpdateSecurityList", "CreateSecurityRule", "DeleteSecurityRule"]
    }
  }
}
