resource "oci_cloud_guard_detector_recipe" "oci-network-infrastructure-010" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-NETWORK-INFRASTRUCTURE-010: CVE-2026-20079 \u2014 Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-20079: Cisco Secure Firewall Management Center (FMC) Software and Cisco Security Cloud Control (SCC) Firewall Management contain an authentication Bypass using an alternate path or channel vulnerability that could allow an unauthenticated, remote attacker to bypass authentication and execute script files on an affected device to obtain root access to the underlying operating system.. Product: Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-NETWORK-INFRASTRUCTURE-010_conditions"
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
      rule_id       = "OCI-NETWORK-INFRASTRUCTURE-010"
      category      = "network-infrastructure"
      mitre_attack  = ["T1548", "T1078", "T1110"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdatePolicy", "CreatePolicy", "AddUserToGroup", "UpdateUserCapabilities"]
    }
  }
}
