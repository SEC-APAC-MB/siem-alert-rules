resource "oci_cloud_guard_detector_recipe" "oci-ai_llm_attacks-042" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI_LLM_ATTACKS-042: Indirect Prompt Injection"
  description     = "Detection rules for AI-specific attacks: prompt injection, model manipulation, data exfiltration, training data extraction"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI_LLM_ATTACKS-042_conditions"
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
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateUser"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AddUserToGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "InstanceAction"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AI_LLM_ATTACKS-042"
      category      = "ai_llm_attacks"
      mitre_attack  = []
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateAuthToken", "CreateApiKey", "UpdatePolicy", "CreatePolicy", "UpdateUser", "AddUserToGroup", "InstanceAction"]
    }
  }
}
