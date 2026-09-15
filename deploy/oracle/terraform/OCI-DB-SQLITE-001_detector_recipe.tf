resource "oci_cloud_guard_detector_recipe" "oci-db-sqlite-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-DB-SQLITE-001: SQLite \u2014 Direct File Access from Web"
  description     = "Detects direct SQLite database file access from web applications"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-DB-SQLITE-001_conditions"
      operator   = "OR"

      conditions {
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
    value      = "HeadObject"
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
    value      = "ListPolicies"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-DB-SQLITE-001"
      category      = "general"
      mitre_attack  = ["T1083"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["ListObjects", "ListBuckets", "HeadObject", "GetObject", "ListPolicies"]
    }
  }
}
