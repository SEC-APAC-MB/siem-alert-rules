resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-012" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-012: Lateral movement chain \u2014 VPN \u2192 Internal Recon \u2192 Lateral Movement"
  description     = "Detects VPN compromise followed by internal reconnaissance and lateral movement"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-012_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVpnConnection"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateIPSecConnection"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateRemotePeeringConnection"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateDrg"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateDrg"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-012"
      category      = "general"
      mitre_attack  = ["T1133", "T1087", "T1021"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVpnConnection", "CreateIPSecConnection", "CreateRemotePeeringConnection", "CreateDrg", "UpdateDrg"]
    }
  }
}
