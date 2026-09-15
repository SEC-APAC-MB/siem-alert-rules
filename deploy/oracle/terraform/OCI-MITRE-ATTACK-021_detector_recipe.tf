resource "oci_cloud_guard_detector_recipe" "oci-mitre-attack-021" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-ATTACK-021: MITRE T1055.011: Extra Window Memory Injection"
  description     = "Detects ATT&CK technique T1055.011 (Extra Window Memory Injection). Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-ATTACK-021_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateInstance"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateAutonomousDatabase"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateDatabase"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-ATTACK-021"
      category      = "mitre-attack"
      mitre_attack  = ["T1055.011"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateInstance", "UpdateAutonomousDatabase", "UpdateDatabase"]
    }
  }
}
