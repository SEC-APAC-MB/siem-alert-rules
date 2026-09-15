resource "oci_cloud_guard_detector_recipe" "oci-auth-030" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AUTH-030: Authentication \u2014 Admin Account Enumeration"
  description     = "Detects attempts to enumerate admin or privileged accounts via LDAP or directory queries"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AUTH-030_conditions"
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
      }
    }

    labels = {
      rule_id       = "OCI-AUTH-030"
      category      = "general"
      mitre_attack  = ["T1087.002", "T1087.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["ListUsers", "ListGroups", "ListPolicies"]
    }
  }
}
