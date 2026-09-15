resource "oci_cloud_guard_detector_recipe" "oci-mitre-0639" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MITRE-0639: Data Encrypted for Impact"
  description     = "Detects Data Encrypted for Impact (T1486)"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MITRE-0639_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVault"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "EncryptData"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DisableKey"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "DeleteKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-MITRE-0639"
      category      = "mitre-attack"
      mitre_attack  = ["T1486"]
      compliance    = ["NIST-800-53-SI-4", "PCI-DSS-10.2", "NIS2-Art.15", "DORA-Art.8", "GDPR-32A"]
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVault", "CreateSecret", "EncryptData", "UpdateKey", "DisableKey", "DeleteKey"]
    }
  }
}
