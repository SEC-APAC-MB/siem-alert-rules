resource "oci_cloud_guard_detector_recipe" "oci-db-couch-001" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-DB-COUCH-001: CouchDB \u2014 Admin Party Mode"
  description     = "Detects CouchDB admin party mode or unauthorized admin access"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-DB-COUCH-001_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSession"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "AuthenticateUser"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateApiKey"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-DB-COUCH-001"
      category      = "general"
      mitre_attack  = ["T1078.001"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateSession", "AuthenticateUser", "CreateApiKey"]
    }
  }
}
