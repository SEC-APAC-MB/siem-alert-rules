resource "oci_cloud_guard_detector_recipe" "oci-mitre-0612" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-0612: Indicator Removal: File Deletion"
  description     = "Detects Indicator Removal: File Deletion (T1070.004)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-0612_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteFile"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteBucket"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-0612"
      category      = "mitre-attack"
      mitre_attack  = ["T1070.004"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["DeleteFile", "DeleteObject", "DeleteBucket"]
    }
  }
}
