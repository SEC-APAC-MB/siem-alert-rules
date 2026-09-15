resource "oci_cloud_guard_detector_recipe" "oci-ai-pd-029" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-PD-029: AI \u2014 Side-Channel Data Exfiltration via Model Outputs"
  description     = "Detects covert data exfiltration channels through model response timing, length, or formatting patterns"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-PD-029_conditions"
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
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AI-PD-029"
      category      = "general"
      mitre_attack  = ["T1566"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "CreateAuthToken", "CreateOrResetUIPassword"]
    }
  }
}
