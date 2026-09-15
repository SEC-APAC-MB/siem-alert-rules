resource "oci_cloud_guard_detector_recipe" "oci-ai-db-031" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-DB-031: AI \u2014 Knowledge Graph Manipulation Attack"
  description     = "Detects manipulation of knowledge graphs used by AI systems for reasoning and entity resolution"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-DB-031_conditions"
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
      rule_id       = "OCI-AI-DB-031"
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
