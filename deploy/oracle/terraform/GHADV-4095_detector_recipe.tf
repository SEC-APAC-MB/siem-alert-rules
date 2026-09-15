resource "oci_cloud_guard_detector_recipe" "ghadv-4095" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-4095: axonflow-sdk-java: Webhook signing-key (HMAC-SHA256) not exposed by SDK type, preventing signature verification"
  description     = "axonflow-sdk-java: Webhook signing-key (HMAC-SHA256) not exposed by SDK type, preventing signature verification"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-4095_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSession"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "Authenticate"
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
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSwiftPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-4095"
      category      = "auth-bypass"
      mitre_attack  = ["T1078"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "Authenticate", "CreateAuthToken", "CreateApiKey", "CreateSwiftPassword"]
    }
  }
}
