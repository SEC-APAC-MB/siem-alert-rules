resource "oci_cloud_guard_detector_recipe" "ghadv-1958" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-1958: http4k: `ServerFilters.DigestAuth` / `DigestAuthProvider` defaulted to an always-true nonce verifier, disabling replay p"
  description     = "http4k: `ServerFilters.DigestAuth` / `DigestAuthProvider` defaulted to an always-true nonce verifier, disabling replay protection in default deployments"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-1958_conditions"
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
      rule_id       = "GHADV-1958"
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
