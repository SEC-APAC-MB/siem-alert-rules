resource "oci_cloud_guard_detector_recipe" "oci-wstg10-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG10-001: Business Logic \u2014 Price Manipulation"
  description     = "Detects price manipulation attempts via negative quantities, zero-price items, or modified totals in checkout"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG10-001_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecurityRule"
    data_type  = "STRING"
  }
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
    value      = "CreateNetworkSecurityGroup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-WSTG10-001"
      category      = "general"
      mitre_attack  = ["T1498"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSecurityRule", "UpdateNetworkSecurityGroup", "UpdateSecurityList", "CreateNetworkSecurityGroup"]
    }
  }
}
