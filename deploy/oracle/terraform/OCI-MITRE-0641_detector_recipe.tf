resource "oci_cloud_guard_detector_recipe" "oci-mitre-0641" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-0641: Inhibit System Recovery"
  description     = "Detects Inhibit System Recovery (T1490)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-0641_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteVolumeBackup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteBootVolumeBackup"
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
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeletePolicy"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-0641"
      category      = "mitre-attack"
      mitre_attack  = ["T1490"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["DeleteVolumeBackup", "DeleteBootVolumeBackup", "DeleteObject", "DeleteBucket", "DeletePolicy"]
    }
  }
}
