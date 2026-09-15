resource "oci_cloud_guard_detector_recipe" "oci-mitre-attack-022" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-ATTACK-022: MITRE T1053.005: Scheduled Task"
  description     = "Detects ATT&CK technique T1053.005 (Scheduled Task). Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The ["
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-ATTACK-022_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateScheduledJob"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateScheduledJob"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateJob"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateJob"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-ATTACK-022"
      category      = "mitre-attack"
      mitre_attack  = ["T1053.005"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateScheduledJob", "UpdateScheduledJob", "CreateJob", "UpdateJob"]
    }
  }
}
