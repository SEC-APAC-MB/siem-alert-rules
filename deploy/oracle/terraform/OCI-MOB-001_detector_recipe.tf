resource "oci_cloud_guard_detector_recipe" "oci-mob-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MOB-001: Mobile \u2014 Insecure Data Storage on Device"
  description     = "Detects mobile app data storage issues including unencrypted SQLite databases and shared preferences"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MOB-001_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetSecretBundle"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListSecrets"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListSecretBundles"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MOB-001"
      category      = "general"
      mitre_attack  = ["T1552.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["GetSecret", "GetSecretBundle", "ListSecrets", "ListSecretBundles"]
    }
  }
}
