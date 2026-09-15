resource "oci_cloud_guard_detector_recipe" "oci-exfiltration-161" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-EXFILTRATION-161: Email Data Exfiltration"
  description     = "Detect bulk email forwarding rules or auto-forwarding to external addresses"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-EXFILTRATION-161_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CopyObject"
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
    value      = "CreateObject"
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
    value      = "CreateBucket"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateBucket"
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
      rule_id       = "OCI-EXFILTRATION-161"
      category      = "exfiltration"
      mitre_attack  = []
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CopyObject", "PutObject", "CreateObject", "GetObject", "CreateBucket", "UpdateBucket", "DeleteObject"]
    }
  }
}
