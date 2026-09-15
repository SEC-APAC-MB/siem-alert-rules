resource "oci_cloud_guard_detector_recipe" "oci-mob-006" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-MOB-006: Mobile \u2014 Certificate Pinning Bypass"
  description     = "Detects SSL/TLS certificate pinning bypass attempts on mobile applications"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-MOB-006_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateNetworkSecurityGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateSecurityRule"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreateSecurityRule"
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
      rule_id       = "OCI-MOB-006"
      category      = "general"
      mitre_attack  = ["T1557"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["UpdateNetworkSecurityGroup", "UpdateSecurityRule", "CreateSecurityRule", "UpdateDnsResolver"]
    }
  }
}
