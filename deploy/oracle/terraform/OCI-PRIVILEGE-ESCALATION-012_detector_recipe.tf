resource "oci_cloud_guard_detector_recipe" "oci-privilege-escalation-012" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-PRIVILEGE-ESCALATION-012: CVE-2026-53362 \u2014 Kernel Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-53362: Linux Kernel contains an unspecified vulnerability that can allow for privilege escalation via IPv6 networking subsystem. This vulnerability can impact multiple products, including but not limited to Suse, Red Hat, and other products using Linux. . Product: Kernel"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-PRIVILEGE-ESCALATION-012_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePolicy"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AddUserToGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateUserCapabilities"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-PRIVILEGE-ESCALATION-012"
      category      = "privilege-escalation"
      mitre_attack  = ["T1548"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdatePolicy", "CreatePolicy", "AddUserToGroup", "UpdateUserCapabilities"]
    }
  }
}
