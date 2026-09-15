resource "oci_cloud_guard_detector_recipe" "oci-db-redis-002" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-DB-REDIS-002: Redis \u2014 FLUSHALL/FLUSHDB Data Destruction"
  description     = "Detects Redis FLUSHALL or FLUSHDB commands indicating potential data destruction"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-DB-REDIS-002_conditions"
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
      rule_id       = "OCI-DB-REDIS-002"
      category      = "general"
      mitre_attack  = ["T1485"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateAutonomousDatabase", "AutonomousDatabaseDataSafe", "ChangeAutonomousDatabaseAdminPassword", "CreateAutonomousDatabaseBackup", "RotateAutonomousDatabaseEncryptionKey"]
    }
  }
}
