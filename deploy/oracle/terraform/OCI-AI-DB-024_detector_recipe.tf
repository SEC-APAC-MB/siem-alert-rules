resource "oci_cloud_guard_detector_recipe" "oci-ai-db-024" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-DB-024: AI \u2014 RAG Access Control Bypass"
  description     = "Detects bypass of document-level access controls in RAG systems exposing unauthorized content"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-DB-024_conditions"
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
      rule_id       = "OCI-AI-DB-024"
      category      = "general"
      mitre_attack  = ["T1567", "T1552"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateObject", "PutObject", "CopyObject", "GetObject", "CreateBucket"]
    }
  }
}
