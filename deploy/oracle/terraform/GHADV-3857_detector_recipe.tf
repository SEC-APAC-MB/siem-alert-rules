resource "oci_cloud_guard_detector_recipe" "ghadv-3857" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-3857: Vert.x has a DoS via unbounded server-side SNI SslContext cache growth"
  description     = "Vert.x has a DoS via unbounded server-side SNI SslContext cache growth"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-3857_conditions"
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
      rule_id       = "GHADV-3857"
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
