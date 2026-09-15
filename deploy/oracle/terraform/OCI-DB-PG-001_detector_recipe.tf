resource "oci_cloud_guard_detector_recipe" "oci-db-pg-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-DB-PG-001: PostgreSQL \u2014 Privilege Escalation via SET ROLE"
  description     = "Detects PostgreSQL SET ROLE attempts for privilege escalation"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-DB-PG-001_conditions"
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
      }
    }

    labels = {
      rule_id       = "OCI-DB-PG-001"
      category      = "general"
      mitre_attack  = ["T1548"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateAutonomousDatabase", "AutonomousDatabaseDataSafe", "ChangeAutonomousDatabaseAdminPassword"]
    }
  }
}
