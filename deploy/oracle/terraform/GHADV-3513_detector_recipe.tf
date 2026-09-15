resource "oci_cloud_guard_detector_recipe" "ghadv-3513" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-3513: epa4all-client: TLS Certificate Validation Disabled in Production"
  description     = "epa4all-client: TLS Certificate Validation Disabled in Production"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-3513_conditions"
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
    value      = "UpdateSecret"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "GetSecret"
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
    value      = "DecryptData"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-3513"
      category      = "tls"
      mitre_attack  = ["T1573", "T1526"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVault", "CreateSecret", "UpdateSecret", "GetSecret", "EncryptData", "DecryptData"]
    }
  }
}
