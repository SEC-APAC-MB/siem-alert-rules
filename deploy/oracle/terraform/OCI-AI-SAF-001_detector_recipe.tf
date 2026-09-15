resource "oci_cloud_guard_detector_recipe" "oci-ai-saf-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-SAF-001: AI \u2014 Safety \u2014 Harmful Content Generation"
  description     = "Detects LLM attempts to generate harmful content including weapons, drugs, or dangerous instructions"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-SAF-001_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateLoadBalancer"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateLoadBalancer"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateNetworkLoadBalancer"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AI-SAF-001"
      category      = "general"
      mitre_attack  = ["T1190"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "CreateLoadBalancer", "UpdateLoadBalancer", "CreateNetworkLoadBalancer"]
    }
  }
}
