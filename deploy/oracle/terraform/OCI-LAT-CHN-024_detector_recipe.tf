resource "oci_cloud_guard_detector_recipe" "oci-lat-chn-024" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-LAT-CHN-024: Lateral movement chain \u2014 Cloud Storage \u2192 Key Theft \u2192 Subscription Takeover"
  description     = "Detects cloud storage access followed by key theft and subscription takeover"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-LAT-CHN-024_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListObjects"
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
    value      = "CreateObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "PutObject"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-LAT-CHN-024"
      category      = "general"
      mitre_attack  = ["T1530", "T1552.001", "T1078"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["GetObject", "ListObjects", "HeadObject", "CreateObject", "PutObject"]
    }
  }
}
