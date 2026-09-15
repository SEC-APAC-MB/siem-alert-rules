resource "oci_cloud_guard_detector_recipe" "oci-db-tscale-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-DB-TSCALE-001: TimescaleDB \u2014 Hypertable Data Exfiltration"
  description     = "Detects bulk data extraction from TimescaleDB hypertables"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-DB-TSCALE-001_conditions"
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
      rule_id       = "OCI-DB-TSCALE-001"
      category      = "general"
      mitre_attack  = ["T1213"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateAutonomousDatabase", "AutonomousDatabaseDataSafe", "ChangeAutonomousDatabaseAdminPassword", "CreateAutonomousDatabaseBackup", "RotateAutonomousDatabaseEncryptionKey"]
    }
  }
}
