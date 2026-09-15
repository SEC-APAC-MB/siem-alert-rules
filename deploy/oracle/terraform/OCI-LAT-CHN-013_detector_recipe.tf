resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-013" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-013: Lateral movement chain \u2014 DNS Tunnel \u2192 Data Exfiltration"
  description     = "Detects DNS tunneling followed by data exfiltration through DNS channels"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-013_conditions"
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
    value      = "InstanceAction"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePrivateIp"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateDnsResolver"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-013"
      category      = "general"
      mitre_attack  = ["T1071.004", "T1048"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "InstanceAction", "CreatePrivateIp", "UpdateDnsResolver"]
    }
  }
}
