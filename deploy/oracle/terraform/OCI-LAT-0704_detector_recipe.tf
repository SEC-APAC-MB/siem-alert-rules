resource "oci_cloud_guard_detector_recipe" "oci-lat-0704" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-0704: Lateral Movement: PsExec Followed by Discovery"
  description     = "Correlation rule detecting psexec followed by discovery"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-0704_conditions"
      operator   = "OR"

      conditions {
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
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVnic"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateVnic"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "InstanceAction"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-0704"
      category      = "lateral-movement"
      mitre_attack  = ["T1021.002", "T1082"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreatePrivateIp", "UpdatePrivateIp", "CreateVnic", "UpdateVnic", "InstanceAction"]
    }
  }
}
