resource "oci_cloud_guard_detector_recipe" "ghadv-3351" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-3351: fabric-chaincode-java: TLS Private Key Password Disclosed in INFO Startup Logs in Chaincode-as-a-Service Mode"
  description     = "fabric-chaincode-java: TLS Private Key Password Disclosed in INFO Startup Logs in Chaincode-as-a-Service Mode"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-3351_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListUsers"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListGroups"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListPolicies"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListUserGroups"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListApiKeys"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListAuthTokens"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-3351"
      category      = "info-disclosure"
      mitre_attack  = ["T1087"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["ListUsers", "ListGroups", "ListPolicies", "ListUserGroups", "ListApiKeys", "ListAuthTokens"]
    }
  }
}
