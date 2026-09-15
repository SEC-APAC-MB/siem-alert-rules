resource "oci_cloud_guard_detector_recipe" "oci-ai-pd-022" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-PD-022: AI \u2014 Automated Prompt Fuzzing"
  description     = "Detects automated fuzzing of AI model prompts to discover vulnerabilities"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-PD-022_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListObjects"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListBuckets"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "HeadObject"
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
    value      = "ListPolicies"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AI-PD-022"
      category      = "general"
      mitre_attack  = ["T1083"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["ListObjects", "ListBuckets", "HeadObject", "GetObject", "ListPolicies"]
    }
  }
}
