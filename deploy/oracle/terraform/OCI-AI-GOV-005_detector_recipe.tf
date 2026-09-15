resource "oci_cloud_guard_detector_recipe" "oci-ai-gov-005" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-GOV-005: AI \u2014 Bias Detection Alert"
  description     = "Detects AI model outputs exhibiting statistical bias across protected demographic groups"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-GOV-005_conditions"
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
      rule_id       = "OCI-AI-GOV-005"
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
