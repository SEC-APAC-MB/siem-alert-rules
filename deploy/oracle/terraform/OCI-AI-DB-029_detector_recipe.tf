resource "oci_cloud_guard_detector_recipe" "oci-ai-db-029" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-DB-029: AI \u2014 Vector Database Credential Theft"
  description     = "Detects credential theft targeting vector database authentication mechanisms"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-DB-029_conditions"
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
      rule_id       = "OCI-AI-DB-029"
      category      = "general"
      mitre_attack  = ["T1552", "T1110"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSecret", "UpdateSecret", "GetSecret", "GetSecretBundle", "ListSecrets"]
    }
  }
}
