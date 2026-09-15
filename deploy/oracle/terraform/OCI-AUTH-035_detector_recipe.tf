resource "oci_cloud_guard_detector_recipe" "oci-auth-035" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AUTH-035: Authentication \u2014 Downgrade Attack on Auth Protocol"
  description     = "Detects authentication protocol downgrade from Kerberos to NTLM indicating potential downgrade attacks"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AUTH-035_conditions"
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
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateDnsResolver"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AUTH-035"
      category      = "general"
      mitre_attack  = ["T1557"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateNetworkSecurityGroup", "UpdateSecurityRule", "CreateSecurityRule", "UpdateDnsResolver"]
    }
  }
}
