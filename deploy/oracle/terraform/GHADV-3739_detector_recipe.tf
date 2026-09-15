resource "oci_cloud_guard_detector_recipe" "ghadv-3739" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-3739: Spring AI: ChatMemory DEFAULT_CONVERSATION_ID causes unintended cross-user data leakage"
  description     = "Spring AI: ChatMemory DEFAULT_CONVERSATION_ID causes unintended cross-user data leakage"
  detector        = "OCI_CONFIGURATION"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-3739_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventType"
    operator   = "IN"
    value      = "UpdateVcn,UpdateSubnet,UpdateSecurityList,UpdateNetworkSecurityGroup,UpdateBucket"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-3739"
      category      = "misconfiguration"
      mitre_attack  = ["T1574"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_CONFIGURATION"
      namespace   = "Compliance"
      events      = ["UpdateVcn", "UpdateSubnet", "UpdateSecurityList", "UpdateNetworkSecurityGroup", "UpdateBucket", "UpdatePolicy", "UpdateAutonomousDatabase"]
    }
  }
}
