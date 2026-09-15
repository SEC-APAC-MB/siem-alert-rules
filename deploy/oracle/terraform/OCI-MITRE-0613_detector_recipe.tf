resource "oci_cloud_guard_detector_recipe" "oci-mitre-0613" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-0613: Impair Defenses: Disable Tools"
  description     = "Detects Impair Defenses: Disable Tools (T1562.001)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-0613_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteDetectorRecipe"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateDetectorRecipe"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteLog"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateLog"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteLogGroup"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-0613"
      category      = "mitre-attack"
      mitre_attack  = ["T1562.001"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["DeleteDetectorRecipe", "UpdateDetectorRecipe", "DeleteLog", "UpdateLog", "DeleteLogGroup"]
    }
  }
}
