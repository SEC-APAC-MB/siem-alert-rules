resource "oci_cloud_guard_detector_recipe" "oci-ransomware-082" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-RANSOMWARE-082: Ransomware C2 Beacon Pattern"
  description     = "Detection rules for ransomware indicators: encryption patterns, C2 behavior, lateral movement preceding ransomware deployment"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-RANSOMWARE-082_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVault"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "EncryptData"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DisableKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ScheduleKeyDeletion"
    data_type  = "STRING"
  }
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
    value      = "DeleteInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "TerminateInstance"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-RANSOMWARE-082"
      category      = "ransomware"
      mitre_attack  = []
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVault", "CreateSecret", "EncryptData", "DisableKey", "DeleteKey", "ScheduleKeyDeletion", "DeleteVolumeBackup", "DeleteBootVolumeBackup", "DeleteInstance", "TerminateInstance"]
    }
  }
}
