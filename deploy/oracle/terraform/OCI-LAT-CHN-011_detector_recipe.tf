resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-011" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-011: Lateral movement chain \u2014 Exploit \u2192 Shell \u2192 Network Propagation"
  description     = "Detects exploitation followed by shell access and network propagation across multiple hosts"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-011_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateLoadBalancer"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateLoadBalancer"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateNetworkLoadBalancer"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-011"
      category      = "general"
      mitre_attack  = ["T1190", "T1059", "T1021"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "CreateLoadBalancer", "UpdateLoadBalancer", "CreateNetworkLoadBalancer"]
    }
  }
}
