resource "oci_cloud_guard_detector_recipe" "ghadv-2621" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-2621: Spring Data REST potentially exposes persistence-layer internals to HTTP clients"
  description     = "Spring Data REST potentially exposes persistence-layer internals to HTTP clients"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-2621_conditions"
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
    value      = "ListBuckets"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListInstances"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListAutonomousDbs"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetSecretBundle"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-2621"
      category      = "info-disclosure"
      mitre_attack  = ["T1592"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["GetObject", "ListObjects", "ListBuckets", "GetInstance", "ListInstances", "ListAutonomousDbs", "GetSecret", "GetSecretBundle"]
    }
  }
}
