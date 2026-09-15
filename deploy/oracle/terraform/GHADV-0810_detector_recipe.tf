resource "oci_cloud_guard_detector_recipe" "ghadv-0810" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-0810: Netty: TOCTOU in OcspServerCertificateValidator"
  description     = "Netty: TOCTOU in OcspServerCertificateValidator"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-0810_conditions"
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
    value      = "UpdateInstance"
    data_type  = "STRING"
  }
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
    value      = "UpdateAutonomousDatabase"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateVolumeAttachment"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-0810"
      category      = "race-condition"
      mitre_attack  = ["T1054"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "UpdateInstance", "CreateObject", "PutObject", "UpdateAutonomousDatabase", "CreateVolumeAttachment"]
    }
  }
}
