resource "oci_cloud_guard_detector_recipe" "oci-db-pg-003" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-DB-PG-003: PostgreSQL \u2014 Row-Level Security Bypass"
  description     = "Detects PostgreSQL queries bypassing row-level security policies"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-DB-PG-003_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GenerateAutonomousDatabaseWallet"
    data_type  = "STRING"
  }
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
      }
    }

    labels = {
      rule_id       = "OCI-DB-PG-003"
      category      = "general"
      mitre_attack  = ["T1078"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["GenerateAutonomousDatabaseWallet", "UpdateAutonomousDatabase", "AutonomousDatabaseDataSafe"]
    }
  }
}
