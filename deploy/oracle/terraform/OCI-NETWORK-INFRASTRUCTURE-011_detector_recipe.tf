resource "oci_cloud_guard_detector_recipe" "oci-network-infrastructure-011" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-NETWORK-INFRASTRUCTURE-011: CVE-2026-20349 \u2014 Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD)  Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-20349: Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) contain a heap inspection vulnerability that could allow an unauthenticated, remote attacker to cause the device to reload unexpectedly, resulting in a denial of service (DoS) condition.. Product: Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) "
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-NETWORK-INFRASTRUCTURE-011_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecurityRule"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateNetworkSecurityGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecurityList"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateNetworkSecurityGroup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-NETWORK-INFRASTRUCTURE-011"
      category      = "network-infrastructure"
      mitre_attack  = ["T1498", "T1110", "T1078"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSecurityRule", "UpdateNetworkSecurityGroup", "UpdateSecurityList", "CreateNetworkSecurityGroup"]
    }
  }
}
