resource "oci_cloud_guard_detector_recipe" "oci-general-017" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-GENERAL-017: CVE-2026-8452 \u2014 NetScaler ADC and NetScaler Gateway Exploitation"
  description     = "Detects exploitation attempts targeting CVE-2026-8452: Citrix NetScaler ADC and NetScaler Gateway contain an improper restriction of operations within the bounds of a memory buffer vulnerability which could lead to denial of service. . Product: NetScaler ADC and NetScaler Gateway"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-GENERAL-017_conditions"
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
      rule_id       = "OCI-GENERAL-017"
      category      = "general"
      mitre_attack  = ["T1498"]
      compliance    = ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSecurityRule", "UpdateNetworkSecurityGroup", "UpdateSecurityList", "CreateNetworkSecurityGroup"]
    }
  }
}
