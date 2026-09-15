resource "oci_cloud_guard_detector_recipe" "oci-remote-code-execution-013" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-REMOTE-CODE-EXECUTION-013: CVE-2026-72530 \u2014 Server Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-72530: TrueConf Server contains a code injection vulnerability that could allow an unauthorized remote attacker with network access via port 4307/TCP to use a specially crafted script to break out of the isolated environment and execute arbitrary code on the host system.. Product: Server"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-REMOTE-CODE-EXECUTION-013_conditions"
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
      rule_id       = "OCI-REMOTE-CODE-EXECUTION-013"
      category      = "remote-code-execution"
      mitre_attack  = ["T1110", "T1059", "T1078", "T1190"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateApiKey", "CreateSwiftPassword", "CreateDbCredential", "CreateOrResetUIPassword"]
    }
  }
}
