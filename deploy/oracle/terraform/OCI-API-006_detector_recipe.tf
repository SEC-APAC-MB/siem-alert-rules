resource "oci_cloud_guard_detector_recipe" "oci-api-006" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-API-006: API6: Unrestricted Access to Sensitive Business Flows"
  description     = "Detects automated or excessive access to business-critical API flows like checkout, transfer, or account creation"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-API-006_conditions"
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
    value      = "GetApiDeployment"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListApiDeployments"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-API-006"
      category      = "general"
      mitre_attack  = ["T1498"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateApiDeployment", "UpdateApiDeployment", "GetApiDeployment", "ListApiDeployments"]
    }
  }
}
