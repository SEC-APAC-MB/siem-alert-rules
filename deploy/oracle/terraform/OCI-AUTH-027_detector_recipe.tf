resource "oci_cloud_guard_detector_recipe" "oci-auth-027" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AUTH-027: Authentication \u2014 Credential Relaying via NTLM"
  description     = "Detects NTLM relay attacks forwarding authentication to downstream servers"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AUTH-027_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateNetworkSecurityGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecurityRule"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecurityRule"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AUTH-027"
      category      = "general"
      mitre_attack  = ["T1557.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateNetworkSecurityGroup", "UpdateSecurityRule", "CreateSecurityRule"]
    }
  }
}
