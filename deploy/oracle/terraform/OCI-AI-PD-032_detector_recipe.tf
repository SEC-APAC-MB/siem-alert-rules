resource "oci_cloud_guard_detector_recipe" "oci-ai-pd-032" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-AI-PD-032: AI \u2014 Prompt Caching Attack"
  description     = "Detects attacks exploiting prompt caching mechanisms to inject persistent instructions"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-AI-PD-032_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVault"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DecryptData"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "EncodeData"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-AI-PD-032"
      category      = "general"
      mitre_attack  = ["T1059", "T1140"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSecret", "UpdateSecret", "CreateVault", "DecryptData", "EncodeData"]
    }
  }
}
