resource "oci_cloud_guard_detector_recipe" "oci-ai-vec-002" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-VEC-002: AI \u2014 Vector DB \u2014 Weaviate Tenant Data Isolation Failure"
  description     = "Detects cross-tenant data access in Weaviate vector database"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-VEC-002_conditions"
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
      rule_id       = "OCI-AI-VEC-002"
      category      = "general"
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
