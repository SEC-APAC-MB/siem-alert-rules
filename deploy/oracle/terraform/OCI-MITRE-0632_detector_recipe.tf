resource "oci_cloud_guard_detector_recipe" "oci-mitre-0632" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-0632: Application Layer: DNS"
  description     = "Detects Application Layer: DNS (T1071.004)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-0632_conditions"
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
    value      = "InstanceAction"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePrivateIp"
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
      rule_id       = "OCI-MITRE-0632"
      category      = "mitre-attack"
      mitre_attack  = ["T1071.004"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "InstanceAction", "CreatePrivateIp", "UpdateDnsResolver"]
    }
  }
}
