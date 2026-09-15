resource "oci_cloud_guard_detector_recipe" "oci-remote-code-execution-005" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-REMOTE-CODE-EXECUTION-005: CVE-2026-9586 \u2014 Switchvox Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-9586: Sangoma Switchvox contains a SQL injection vulnerability which allows an unauthenticated remote attacker to execute arbitrary SQL statements against the backend PostgreSQL database using a single crafted request, including database operations and remote code execution.. Product: Switchvox"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-REMOTE-CODE-EXECUTION-005_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateAuthToken"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSwiftPassword"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateDbCredential"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateOrResetUIPassword"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-REMOTE-CODE-EXECUTION-005"
      category      = "remote-code-execution"
      mitre_attack  = ["T1110", "T1078", "T1059", "T1190"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateApiKey", "CreateSwiftPassword", "CreateDbCredential", "CreateOrResetUIPassword"]
    }
  }
}
