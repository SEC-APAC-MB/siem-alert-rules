resource "oci_cloud_guard_detector_recipe" "oci-ai-pd-038" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-PD-038: AI \u2014 Cross-Modal Injection Attack"
  description     = "Detects prompt injection through cross-modal inputs (text in images, audio commands, video overlays)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-PD-038_conditions"
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
    value      = "CreatePrivateIp"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVnic"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "InstanceAction"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecurityRule"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AI-PD-038"
      category      = "general"
      mitre_attack  = ["T1189", "T1078"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "CreatePrivateIp", "CreateVnic", "InstanceAction", "UpdateSecurityRule"]
    }
  }
}
