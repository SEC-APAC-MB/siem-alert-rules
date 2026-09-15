resource "oci_cloud_guard_detector_recipe" "oci-mitre-attack-031" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-ATTACK-031: MITRE T1557: Adversary-in-the-Middle"
  description     = "Detects ATT&CK technique T1557 (Adversary-in-the-Middle). Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as [Network Sniffing](https:/"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-ATTACK-031_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateNetworkSecurityGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecurityRule"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecurityRule"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateDnsResolver"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-ATTACK-031"
      category      = "mitre-attack"
      mitre_attack  = ["T1557"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateNetworkSecurityGroup", "UpdateSecurityRule", "CreateSecurityRule", "UpdateDnsResolver"]
    }
  }
}
