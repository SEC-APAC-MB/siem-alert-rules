resource "oci_cloud_guard_detector_recipe" "oci-ai-db-020" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-DB-020: AI \u2014 Sensitive Data Exposure via RAG Output"
  description     = "Detects exposure of sensitive data through RAG output that should have been filtered by access controls"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-DB-020_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "PutObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CopyObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateBucket"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AI-DB-020"
      category      = "general"
      mitre_attack  = ["T1567"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateObject", "PutObject", "CopyObject", "GetObject", "CreateBucket"]
    }
  }
}
