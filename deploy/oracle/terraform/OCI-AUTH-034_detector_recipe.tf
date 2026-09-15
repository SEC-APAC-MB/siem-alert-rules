resource "oci_cloud_guard_detector_recipe" "oci-auth-034" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AUTH-034: Authentication \u2014 Forged PAC Attack"
  description     = "Detects privilege attribute certificate manipulation in Kerberos tickets"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AUTH-034_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
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
    value      = "GetAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListApiKeys"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AUTH-034"
      category      = "general"
      mitre_attack  = ["T1558"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateApiKey", "GetAuthToken", "ListApiKeys"]
    }
  }
}
