resource "oci_cloud_guard_detector_recipe" "oci-pci-021" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PCI-021: PCI-DSS \u2014 Insider Threat Card Data Access Anomaly"
  description     = "Detects anomalous access patterns to cardholder data by insiders indicating potential data theft"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PCI-021_conditions"
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
      rule_id       = "OCI-PCI-021"
      category      = "general"
      mitre_attack  = ["T1530", "T1567"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateNetworkSecurityGroup", "UpdateSecurityList", "CreateSecurityRule", "DeleteSecurityRule"]
    }
  }
}
