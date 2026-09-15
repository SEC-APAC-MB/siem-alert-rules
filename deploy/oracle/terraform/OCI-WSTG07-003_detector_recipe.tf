resource "oci_cloud_guard_detector_recipe" "oci-wstg07-003" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG07-003: Cross-Site Scripting (XSS) Stored"
  description     = "Detects stored XSS patterns where malicious scripts are persisted and served to other users"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG07-003_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiDeployment"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateApiDeployment"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "InvokeFunction"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-WSTG07-003"
      category      = "general"
      mitre_attack  = ["T1059.007"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "CreateInstance", "UpdateInstance", "InvokeFunction"]
    }
  }
}
