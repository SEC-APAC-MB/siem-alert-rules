resource "oci_cloud_guard_detector_recipe" "oci-db-mss-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-DB-MSS-001: SQL Server \u2014 xp_cmdshell Execution"
  description     = "Detects execution of xp_cmdshell stored procedure enabling OS command execution"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-DB-MSS-001_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateAutonomousDatabase"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AutonomousDatabaseDataSafe"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ChangeAutonomousDatabaseAdminPassword"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAutonomousDatabaseBackup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "RotateAutonomousDatabaseEncryptionKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-DB-MSS-001"
      category      = "general"
      mitre_attack  = ["T1059"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateAutonomousDatabase", "AutonomousDatabaseDataSafe", "ChangeAutonomousDatabaseAdminPassword", "CreateAutonomousDatabaseBackup", "RotateAutonomousDatabaseEncryptionKey"]
    }
  }
}
