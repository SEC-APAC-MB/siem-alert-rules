resource "oci_cloud_guard_detector_recipe" "oci-general-014" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-GENERAL-014: CVE-2026-8037 \u2014 LoadMaster Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-8037: Progress LoadMaster contains a command injection vulnerability that allows an un-authenticated attacker to execute arbitrary commands on the LoadMaster appliance by exploiting unsanitized input in multiple command endpoints.. Product: LoadMaster"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-GENERAL-014_conditions"
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
      rule_id       = "OCI-GENERAL-014"
      category      = "general"
      mitre_attack  = ["T1110", "T1078"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateAuthToken", "CreateApiKey", "CreateSwiftPassword", "CreateDbCredential", "CreateOrResetUIPassword"]
    }
  }
}
