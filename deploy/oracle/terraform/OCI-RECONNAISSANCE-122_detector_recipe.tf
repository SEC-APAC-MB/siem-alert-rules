resource "oci_cloud_guard_detector_recipe" "oci-reconnaissance-122" {
  compartment_id  = var.compartment_id
  display_name    = "OCI-RECONNAISSANCE-122: SSL/TLS Certificate Reconnaissance"
  description     = "Detect certificate transparency log scraping and subdomain discovery"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "OCI-RECONNAISSANCE-122_conditions"
      operator   = "OR"

      conditions {
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListInstances"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListVcns"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListSubnets"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListSecurityLists"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListPolicies"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListUsers"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListGroups"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListBuckets"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListObjects"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "ListDatabases"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "OCI-RECONNAISSANCE-122"
      category      = "reconnaissance"
      mitre_attack  = []
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["ListInstances", "ListVcns", "ListSubnets", "ListSecurityLists", "ListPolicies", "ListUsers", "ListGroups", "ListBuckets", "ListObjects", "ListDatabases"]
    }
  }
}
