resource "oci_cloud_guard_detector_recipe" "oci-lat-0703" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-0703: Lateral Movement: WMI Remote Execution Followed by Persistence"
  description     = "Correlation rule detecting wmi remote execution followed by persistence"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-0703_conditions"
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
      rule_id       = "OCI-LAT-0703"
      category      = "lateral-movement"
      mitre_attack  = ["T1546.003", "T1547.001"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVpnConnection", "CreateIPSecConnection", "CreateDrg", "UpdateDrg"]
    }
  }
}
