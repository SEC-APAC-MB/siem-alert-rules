resource "oci_cloud_guard_detector_recipe" "oci-mob-002" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MOB-002: Mobile \u2014 Insecure Network Communication"
  description     = "Detects mobile apps communicating over HTTP, using weak TLS, or accepting self-signed certificates"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MOB-002_conditions"
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
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MOB-002"
      category      = "general"
      mitre_attack  = ["T1566"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateAuthToken", "CreateOrResetUIPassword"]
    }
  }
}
