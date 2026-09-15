resource "oci_cloud_guard_detector_recipe" "ghadv-2884" {
  compartment_id  = var.compartment_id
  display_name    = "GHADV-2884: Apache Fluss: Unauthenticated remote attackers can exhaust JVM heap memory using crafted frame headers via TabletServer/"
  description     = "Apache Fluss: Unauthenticated remote attackers can exhaust JVM heap memory using crafted frame headers via TabletServer/CoordinatorServer"
  detector        = "OCI_ACTIVITY"

  detector_rules {
    severity           = "MEDIUM"
    is_enabled         = true

    condition_groups {
      group_name = "GHADV-2884_conditions"
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
    value      = "CreateSecurityRule"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "UpdateNetworkSecurityGroup"
    data_type  = "STRING"
  }
  {
    field_name = "data.eventName"
    operator   = "EQ"
    value      = "CreatePrivateIp"
    data_type  = "STRING"
  }
      }
    }

    labels = {
      rule_id       = "GHADV-2884"
      category      = "dos"
      mitre_attack  = ["T1499"]
      compliance    = []
    }

    data_source_details {
      data_source = "OCI_AUDIT"
      namespace   = "AuditEvents"
      events      = ["CreateInstance", "InstanceAction", "CreateSecurityRule", "UpdateNetworkSecurityGroup", "CreatePrivateIp"]
    }
  }
}
