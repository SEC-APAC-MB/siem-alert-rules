resource "oci_cloud_guard_detector_recipe" "oci-lat-0701" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-0701: Lateral Movement: SSH Followed by Privilege Escalation"
  description     = "Correlation rule detecting ssh followed by privilege escalation"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-0701_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSwiftPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-0701"
      category      = "lateral-movement"
      mitre_attack  = ["T1021.006", "T1548"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiKey", "CreateAuthToken", "CreateOrResetUIPassword", "CreateSwiftPassword"]
    }
  }
}
