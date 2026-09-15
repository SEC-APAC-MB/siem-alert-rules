resource "oci_cloud_guard_detector_recipe" "oci-web-application-017" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-WEB-APPLICATION-017: CVE-2026-34486 \u2014 Tomcat Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-34486: Apache Tomcat contains a missing encryption of sensitive data vulnerability that allows the bypass of the EncryptInterceptor. This vulnerability can be chained with CVE\u20112025\u201124813.. Product: Tomcat"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-WEB-APPLICATION-017_conditions"
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
      rule_id       = "OCI-WEB-APPLICATION-017"
      category      = "web-application"
      mitre_attack  = ["T1059", "T1548", "T1190", "T1592", "T1213"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdatePolicy", "CreatePolicy", "AddUserToGroup", "UpdateUserCapabilities"]
    }
  }
}
