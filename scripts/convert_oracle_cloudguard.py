#!/usr/bin/env python3
"""Convert Oracle SIEM rules to individual OCI Cloud Guard Detector Recipe files.

Each rule becomes one JSON file importable via:
  oci cloud-guard detector-recipe create --from-json <file> --compartment-id <OCID>

Also produces Terraform versions:
  oci_cloud_guard_detector_recipe resource per rule

Output: /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/
"""

import json
import os
import re
import glob

RULES_DIR = "/Users/claw/.openclaw/workspace/siem-alert-rules/rules/oracle"
OUTPUT_DIR = "/Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/detector-recipes"
TF_DIR = "/Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/terraform"
SUMMARY_FILE = "/Users/claw/.openclaw/workspace/siem-alert-rules/deploy/oracle/summary.json"

# Valid OCI Cloud Guard detector types
DETECTOR_TYPES = {
    "OCI_ACTIVITY": "Activity detector — audit log based (OCI AuditEvents)",
    "OCI_CONFIGURATION": "Configuration detector — resource config based",
    "OCI_THREAT": "Threat detector — threat intelligence based",
}

# Valid OCI namespaces
VALID_NAMESPACES = {
    "AuditEvents", "oci_audit", "com.oracle.cloud.audit",
    "com.oracle.cloud.monitoring", "oci_monitoring",
    "oci_vulnerability", "oci_compliance",
    "oci_threatintel", "oci_security",
}

def detect_detector_type(query, rule):
    """Determine the appropriate Cloud Guard detector type from query content."""
    q = query.lower()
    
    # Activity-based (audit events, API calls, logins)
    if any(k in q for k in ["auditevents", "audit", "rEventName", "com.oracle.cloud.audit",
                            "login", "api call", "com.oraclecloud.audit"]):
        return "OCI_ACTIVITY"
    
    # Threat intel based
    if any(k in q for k in ["threat", "malware", "suspicious", "c2", "botnet",
                            "ioc", "indicator"]):
        return "OCI_THREAT"
    
    # Configuration based (security zones, posture)
    if any(k in q for k in ["configuration", "compliance", "posture",
                            "security_zone", "baseline"]):
        return "OCI_CONFIGURATION"
    
    # Default to activity (most SIEM rules are event-based)
    return "OCI_ACTIVITY"


def validate_oci_query(query, rule):
    """Validate the OCI query content."""
    issues = []
    
    if not query or query.strip() == "":
        issues.append("Empty query")
        return "WON'T-WORK", issues
    
    q_lower = query.lower()
    
    # Check if it's generic SQL vs MQL
    if query.strip().upper().startswith("SELECT"):
        # Generic SQL — needs rewrite to MQL or Cloud Guard condition
        issues.append("Query is generic SQL, needs conversion to Cloud Guard detector condition")
        return "NEEDS-REWRITE", issues
    
    # Check for OCI-specific references
    has_oci_ref = any(k in q_lower for k in [
        "oci_monitoring", "compartmentid", "auditevents", "namespace",
        "com.oracle", "oci_audit", "rEventName", "datapoints"
    ])
    
    if not has_oci_ref:
        issues.append("No OCI-specific references found in query")
        return "NEEDS-REWRITE", issues
    
    return "DEPLOY-AS-IS", issues


def severity_to_oci(severity_val, severity_label=None):
    """Convert severity to OCI Cloud Guard severity."""
    if severity_label:
        label = str(severity_label).upper()
        if label in ("CRITICAL",):
            return "CRITICAL"
        elif label in ("HIGH",):
            return "HIGH"
        elif label in ("MEDIUM",):
            return "MEDIUM"
        elif label in ("LOW",):
            return "LOW"
        elif label in ("INFORMATIONAL", "INFO"):
            return "LOW"
    
    if isinstance(severity_val, (int, float)):
        if severity_val >= 4:
            return "CRITICAL"
        elif severity_val >= 3:
            return "HIGH"
        elif severity_val >= 2:
            return "MEDIUM"
        elif severity_val >= 1:
            return "LOW"
        else:
            return "LOW"
    
    return "MEDIUM"


def sanitize_tf_name(name):
    """Convert rule ID to valid Terraform resource name."""
    return re.sub(r'[^a-zA-Z0-9_]', '_', name).lower()


def rule_to_detector_recipe(rule, status, issues):
    """Convert a single rule to an OCI Cloud Guard Detector Recipe JSON."""
    rule_id = rule.get("rule_id", "OCI-UNKNOWN")
    name = rule.get("name", "Unnamed Rule")
    description = rule.get("description", "")
    query = rule.get("query", "")
    severity = severity_to_oci(rule.get("severity", 2), rule.get("severity_label"))
    detector_type = detect_detector_type(query, rule)
    
    tactics = rule.get("tactics", [])
    techniques = rule.get("mitre_attack", [])
    compliance = rule.get("compliance", [])
    
    # Build condition groups from query content
    # Cloud Guard uses conditionGroups with conditions
    condition_groups = []
    if "rEventName" in query or "EventName" in query:
        # Extract event name patterns from query
        event_patterns = re.findall(r"LIKE\s+'%([^']+)%'", query, re.IGNORECASE)
        conditions = []
        for pattern in event_patterns:
            conditions.append({
                "fieldName": "data.eventName",
                "operator": "CONTAINS",
                "value": pattern,
                "dataType": "STRING"
            })
        if conditions:
            condition_groups.append({
                "groupName": f"{rule_id}_conditions",
                "conditions": conditions,
                "operator": "OR"
            })
    
    if not condition_groups:
        # Default condition based on query existence
        condition_groups.append({
            "groupName": f"{rule_id}_default",
            "conditions": [
                {
                    "fieldName": "data.eventName",
                    "operator": "NOT_EMPTY",
                    "value": "",
                    "dataType": "STRING"
                }
            ],
            "operator": "AND"
        })
    
    detector_recipe = {
        "displayName": f"{rule_id}: {name}",
        "description": description,
        "detector": detector_type,
        "detectorRecipeId": rule_id,
        "sourceDetectorRecipeId": None,
        "severity": severity,
        "mappings": {
            "mitreAttackTactics": tactics,
            "mitreAttackTechniques": techniques,
            "compliance": compliance
        },
        "conditionGroups": condition_groups,
        "dataSourceDetails": {
            "dataSource": "OCI_AUDIT" if detector_type == "OCI_ACTIVITY" else "OCI_MONITORING",
            "namespace": "AuditEvents" if detector_type == "OCI_ACTIVITY" else "oci_security",
            "query": query
        },
        "isEnabled": True,
        "labels": {
            "rule_id": rule_id,
            "category": rule.get("category", "general"),
            "severity_label": str(rule.get("severity_label", severity))
        }
    }
    
    if status == "NEEDS-TUNING":
        detector_recipe["description"] += f"\n\n⚠️ NEEDS-TUNING: {'; '.join(issues)}"
    elif status == "NEEDS-REWRITE":
        detector_recipe["description"] += f"\n\n⚠️ NEEDS-REWRITE: {'; '.join(issues)}"
        detector_recipe["dataSourceDetails"]["originalQuery"] = query
        # Provide a rewritten MQL-style condition
        detector_recipe["conditionGroups"] = [{
            "groupName": f"{rule_id}_rewritten",
            "conditions": [{
                "fieldName": "data.eventName",
                "operator": "CONTAINS",
                "value": name.lower().split(":")[0][:50],
                "dataType": "STRING"
            }],
            "operator": "OR"
        }]
    
    return detector_recipe


def rule_to_terraform(rule, status, issues):
    """Convert a single rule to a Terraform oci_cloud_guard_detector_recipe resource."""
    rule_id = rule.get("rule_id", "OCI-UNKNOWN")
    name = rule.get("name", "Unnamed Rule")
    description = rule.get("description", "")
    query = rule.get("query", "")
    severity = severity_to_oci(rule.get("severity", 2), rule.get("severity_label"))
    detector_type = detect_detector_type(query, rule)
    
    tf_name = sanitize_tf_name(rule_id)
    tactics = rule.get("tactics", [])
    techniques = rule.get("mitre_attack", [])
    compliance = rule.get("compliance", [])
    
    tf_resource = {
        "resource": {
            f"oci_cloud_guard_detector_recipe": {
                tf_name: {
                    "compartment_id": "${var.compartment_id}",
                    "display_name": f"{rule_id}: {name}",
                    "description": description,
                    "detector": detector_type,
                    "freeform_tags": {
                        "rule_id": rule_id,
                        "category": rule.get("category", "general"),
                        "compliance": ",".join(compliance) if compliance else "none",
                        "mitre_tactics": ",".join(tactics) if tactics else "none",
                        "mitre_techniques": ",".join(techniques) if techniques else "none",
                        "status": status
                    }
                }
            }
        }
    }
    
    return tf_resource


def process_all_oracle_rules():
    """Process all Oracle rule files and generate Cloud Guard detector recipes."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(TF_DIR, exist_ok=True)
    
    rewrites_dir = os.path.join(OUTPUT_DIR, "rewrites")
    os.makedirs(rewrites_dir, exist_ok=True)
    
    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.json")))
    
    summary = {
        "platform": "oracle",
        "target": "OCI Cloud Guard Detector Recipes",
        "total_files": len(files),
        "total_rules": 0,
        "by_status": {"DEPLOY-AS-IS": 0, "NEEDS-TUNING": 0, "NEEDS-REWRITE": 0, "WON'T-WORK": 0},
        "by_detector_type": {"OCI_ACTIVITY": 0, "OCI_CONFIGURATION": 0, "OCI_THREAT": 0},
        "by_file": {}
    }
    
    for filepath in files:
        filename = os.path.basename(filepath)
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        rules = data.get("rules", [])
        file_stats = {"total": len(rules), "DEPLOY-AS-IS": 0, "NEEDS-TUNING": 0,
                       "NEEDS-REWRITE": 0, "WON'T-WORK": 0}
        
        for rule in rules:
            rule_id = rule.get("rule_id", f"OCI-UNKNOWN-{summary['total_rules']}")
            query = rule.get("query", "")
            
            status, issues = validate_oci_query(query, rule)
            
            file_stats[status] += 1
            summary["by_status"][status] += 1
            summary["total_rules"] += 1
            
            detector_type = detect_detector_type(query, rule)
            summary["by_detector_type"][detector_type] += 1
            
            # Always generate the detector recipe (even for NEEDS-REWRITE — with fixes)
            recipe = rule_to_detector_recipe(rule, status, issues)
            out_file = os.path.join(OUTPUT_DIR, f"{rule_id}_detector_recipe.json")
            with open(out_file, 'w') as f:
                json.dump(recipe, f, indent=2)
            
            # Generate Terraform version
            tf = rule_to_terraform(rule, status, issues)
            tf_file = os.path.join(TF_DIR, f"{sanitize_tf_name(rule_id)}.tf.json")
            with open(tf_file, 'w') as f:
                json.dump(tf, f, indent=2)
            
            # Document issues for non-deployable rules
            if status in ("NEEDS-REWRITE", "WON'T-WORK"):
                issue_file = os.path.join(rewrites_dir, f"{rule_id}_issues.md")
                with open(issue_file, 'w') as f:
                    f.write(f"# {rule_id} — {rule.get('name', 'Unknown')}\n\n")
                    f.write(f"**Status:** {status}\n\n")
                    f.write(f"**Detector Type:** {detector_type}\n\n")
                    f.write(f"**Issues:**\n")
                    for issue in issues:
                        f.write(f"- {issue}\n")
                    f.write(f"\n**Original Query:**\n```\n{query}\n```\n")
                    f.write(f"\n**Recipe file (with rewrite):** {out_file}\n")
        
        summary["by_file"][filename] = file_stats
    
    with open(SUMMARY_FILE, 'w') as f:
        json.dump(summary, f, indent=2)
    
    return summary


if __name__ == "__main__":
    print("Converting Oracle SIEM rules to OCI Cloud Guard Detector Recipes...")
    summary = process_all_oracle_rules()
    print(f"\nDone! {summary['total_rules']} rules processed across {summary['total_files']} files")
    print(f"  DEPLOY-AS-IS:   {summary['by_status']['DEPLOY-AS-IS']}")
    print(f"  NEEDS-TUNING:   {summary['by_status']['NEEDS-TUNING']}")
    print(f"  NEEDS-REWRITE:  {summary['by_status']['NEEDS-REWRITE']}")
    wont = summary['by_status']["WON'T-WORK"]
    print(f"  WON'T-WORK:     {wont}")
    print(f"\nBy detector type:")
    print(f"  OCI_ACTIVITY:      {summary['by_detector_type']['OCI_ACTIVITY']}")
    print(f"  OCI_CONFIGURATION: {summary['by_detector_type']['OCI_CONFIGURATION']}")
    print(f"  OCI_THREAT:        {summary['by_detector_type']['OCI_THREAT']}")
    print(f"\nDetector recipes: {OUTPUT_DIR}")
    print(f"Terraform:        {TF_DIR}")
    print(f"Summary:          {SUMMARY_FILE}")