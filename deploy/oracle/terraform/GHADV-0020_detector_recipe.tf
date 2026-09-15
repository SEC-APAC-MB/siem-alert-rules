resource "oci_cloud_guard_detector_recipe" "ghadv-0020" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-0020: netty-incubator-codec-ohttp: BoringSSL HPKE private key bytes exposed through toString() and exception messages"
  description     = "netty-incubator-codec-ohttp: BoringSSL HPKE private key bytes exposed through toString() and exception messages"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-0020_conditions"
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
      rule_id       = "GHADV-0020"
      category      = "info-disclosure"
      mitre_attack  = ["T1087", "T1592"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["ListUsers", "ListGroups", "ListPolicies", "ListUserGroups", "ListApiKeys", "ListAuthTokens"]
    }
  }
}
