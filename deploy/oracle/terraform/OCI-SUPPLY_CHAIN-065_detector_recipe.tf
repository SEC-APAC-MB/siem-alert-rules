resource "oci_cloud_guard_detector_recipe" "oci-supply_chain-065" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-SUPPLY_CHAIN-065: Unsigned Artifact Deployment"
  description     = "Detection rules for software supply chain attacks: dependency confusion, typosquatting, compromised packages"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-SUPPLY_CHAIN-065_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateImage"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateImage"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateBootVolume"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVolume"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateVolume"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-SUPPLY_CHAIN-065"
      category      = "supply_chain"
      mitre_attack  = []
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateInstance", "CreateImage", "UpdateImage", "CreateBootVolume", "CreateVolume", "UpdateVolume"]
    }
  }
}
