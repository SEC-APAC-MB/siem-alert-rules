resource "oci_cloud_guard_detector_recipe" "oci-mitre-attack-024" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-ATTACK-024: MITRE T1560.001: Archive via Utility"
  description     = "Detects ATT&CK technique T1560.001 (Archive via Utility). Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-ATTACK-024_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "PutObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CopyObject"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateArchive"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-ATTACK-024"
      category      = "mitre-attack"
      mitre_attack  = ["T1560.001"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateObject", "PutObject", "CopyObject", "CreateArchive"]
    }
  }
}
