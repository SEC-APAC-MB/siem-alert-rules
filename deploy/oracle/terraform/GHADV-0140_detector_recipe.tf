resource "oci_cloud_guard_detector_recipe" "ghadv-0140" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-0140: http4k: `DigestAuthProvider.verify` ignored configured algorithm and did not bind to request URI"
  description     = "http4k: `DigestAuthProvider.verify` ignored configured algorithm and did not bind to request URI"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-0140_conditions"
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
      rule_id       = "GHADV-0140"
      category      = "crypto"
      mitre_attack  = ["T1573"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateVault", "CreateSecret", "UpdateSecret", "GetSecret", "EncryptData", "DecryptData"]
    }
  }
}
