resource "oci_cloud_guard_detector_recipe" "oci-db-redis-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-DB-REDIS-001: Redis \u2014 CONFIG GET Credential Exposure"
  description     = "Detects Redis CONFIG commands targeting credentials or authentication configuration"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-DB-REDIS-001_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecret"
    data_type  = "STRING"
  }
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
      }
    }

    labels = {
      rule_id       = "OCI-DB-REDIS-001"
      category      = "general"
      mitre_attack  = ["T1552"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSecret", "UpdateSecret", "GetSecret", "GetSecretBundle", "ListSecrets"]
    }
  }
}
