resource "oci_cloud_guard_detector_recipe" "ghadv-4419" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-4419: OpenMRS Module Upload Vulnerable to Path Traversal (Zip Slip)"
  description     = "OpenMRS Module Upload Vulnerable to Path Traversal (Zip Slip)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-4419_conditions"
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
      rule_id       = "GHADV-4419"
      category      = "path-traversal"
      mitre_attack  = ["T1005", "T1083"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["GetObject", "ListObjects", "HeadObject", "CreateObject", "PutObject"]
    }
  }
}
