resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-006" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-006: Lateral movement chain \u2014 DCOM \u2192 Shell Execute \u2192 C2 Callback"
  description     = "Detects DCOM lateral movement followed by shell execution and command-and-control callback"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-006_conditions"
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
    value      = "CreateVnic"
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
    value      = "UpdateNetworkSecurityGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecurityRule"
    data_type  = "STRING"
  }
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
    value      = "AddUserToGroup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-006"
      category      = "general"
      mitre_attack  = ["T1021.002", "T1559.001", "T1071"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreatePrivateIp", "CreateVnic", "InstanceAction", "UpdateNetworkSecurityGroup", "CreateSecurityRule", "CreateApiKey", "CreateAuthToken", "AddUserToGroup"]
    }
  }
}
