resource "oci_cloud_guard_detector_recipe" "oci-ai-db-032" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-DB-032: AI \u2014 RAG Cache Poisoning"
  description     = "Detects poisoning of RAG response caches that serve malicious content to multiple users"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-DB-032_conditions"
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
    value      = "DeleteObject"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AI-DB-032"
      category      = "general"
      mitre_attack  = ["T1195.001", "T1565"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateObject", "PutObject", "CopyObject", "GetObject", "DeleteObject"]
    }
  }
}
