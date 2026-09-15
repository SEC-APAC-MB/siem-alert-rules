resource "oci_cloud_guard_detector_recipe" "oci-wstg10-004" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG10-004: Business Logic \u2014 Negative Quantity or Amount"
  description     = "Detects transactions with negative quantities or amounts indicating business logic bypass"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG10-004_conditions"
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
      rule_id       = "OCI-WSTG10-004"
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
