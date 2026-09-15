resource "oci_cloud_guard_detector_recipe" "oci-lat-0705" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-0705: Lateral Movement: PowerShell Remoting Followed by Credential Dumping"
  description     = "Correlation rule detecting powershell remoting followed by credential dumping"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-0705_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AddUserToGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateDynamicGroup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-0705"
      category      = "lateral-movement"
      mitre_attack  = ["T1059.001", "T1003.001"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["AddUserToGroup", "CreatePolicy", "UpdatePolicy", "CreateGroup", "CreateDynamicGroup"]
    }
  }
}
