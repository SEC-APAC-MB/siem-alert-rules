resource "oci_cloud_guard_detector_recipe" "oci-mitre-0610" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-0610: Abuse Elevation: Setuid/Setgid"
  description     = "Detects Abuse Elevation: Setuid/Setgid (T1548.001)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-0610_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "SetUserCapabilities"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateUserCapabilities"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateUserState"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-0610"
      category      = "mitre-attack"
      mitre_attack  = ["T1548.001"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["SetUserCapabilities", "UpdateUserCapabilities", "UpdateUserState"]
    }
  }
}
