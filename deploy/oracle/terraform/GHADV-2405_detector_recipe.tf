resource "oci_cloud_guard_detector_recipe" "ghadv-2405" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-2405: Netty: QUIC stateless reset token material exposed through header-visible connection IDs"
  description     = "Netty: QUIC stateless reset token material exposed through header-visible connection IDs"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-2405_conditions"
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
      rule_id       = "GHADV-2405"
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
