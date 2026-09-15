resource "oci_cloud_guard_detector_recipe" "oci-wstg01-013" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WSTG01-013: Cloud Storage Bucket Enumeration"
  description     = "Detects enumeration of cloud storage buckets (S3, GCS, Azure Blob) for data exposure"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WSTG01-013_conditions"
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
    value      = "CreateBucket"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetObject"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-WSTG01-013"
      category      = "general"
      mitre_attack  = ["T1580", "T1537"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CopyObject", "PutObject", "CreateObject", "CreateBucket", "GetObject"]
    }
  }
}
