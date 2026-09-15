resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-001: Lateral Movement chain \u2014 RDP \u2192 Credential Access \u2192 Data Exfiltration"
  description     = "Detects multi-stage lateral movement: initial RDP compromise followed by credential theft and data exfiltration"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-001_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "InstanceAction"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateInstance"
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
    value      = "UpdatePrivateIp"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-001"
      category      = "general"
      mitre_attack  = ["T1021.001", "T1003", "T1567"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["InstanceAction", "CreateInstance", "UpdateInstance", "CreatePrivateIp", "UpdatePrivateIp"]
    }
  }
}
