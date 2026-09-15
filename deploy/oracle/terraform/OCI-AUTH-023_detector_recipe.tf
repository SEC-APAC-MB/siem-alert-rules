resource "oci_cloud_guard_detector_recipe" "oci-auth-023" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AUTH-023: Authentication \u2014 LDAP Simple Bind"
  description     = "Detects LDAP simple bind operations that transmit credentials in cleartext"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AUTH-023_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListVcns"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListSubnets"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListSecurityLists"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListNetworkSecurityGroups"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetSecurityList"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListDrgAttachments"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AUTH-023"
      category      = "general"
      mitre_attack  = ["T1040"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["ListVcns", "ListSubnets", "ListSecurityLists", "ListNetworkSecurityGroups", "GetSecurityList", "ListDrgAttachments"]
    }
  }
}
