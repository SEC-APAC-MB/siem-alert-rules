resource "oci_cloud_guard_detector_recipe" "oci-remote-code-execution-004" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-REMOTE-CODE-EXECUTION-004: CVE-2026-85706 \u2014 Community Edition and Enterprise Edition Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-85706: GitLab Community Edition and Enterprise Edition contains a path traversal vulnerability that allows an unauthenticated user to read arbitrary files due to an improper path confinement and missing authentication enforcement in the repository commits API.. Product: Community Edition and Enterprise Edition"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-REMOTE-CODE-EXECUTION-004_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateLoadBalancer"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateLoadBalancer"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateNetworkLoadBalancer"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-REMOTE-CODE-EXECUTION-004"
      category      = "remote-code-execution"
      mitre_attack  = ["T1059", "T1190", "T1110", "T1078"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "CreateLoadBalancer", "UpdateLoadBalancer", "CreateNetworkLoadBalancer"]
    }
  }
}
