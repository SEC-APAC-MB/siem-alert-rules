#!/usr/bin/env python3
"""Convert Azure SIEM rules to individual ARM template files for Azure Sentinel import.

Each rule becomes one ARM template JSON file that can be deployed via:
  az deployment group create --resource-group <RG> --template-file <file.json>

Output: /Users/claw/.openclaw/workspace/siem-alert-rules/deploy/azure/arm-templates/
"""

import json
import os
import re
import glob

RULES_DIR = "/Users/claw/.openclaw/workspace/siem-alert-rules/rules/azure"
OUTPUT_DIR = "/Users/claw/.openclaw/workspace/siem-alert-rules/deploy/azure/arm-templates"
SUMMARY_FILE = "/Users/claw/.openclaw/workspace/siem-alert-rules/deploy/azure/summary.json"

# Valid Azure Sentinel/KQL table names
VALID_TABLES = {
    "AzureActivity", "SecurityEvent", "SecurityAlert", "SigninLogs", "AzureDiagnostics",
    "AppServiceHTTPLogs", "AppRequests", "AppServiceAuditLogs", "AppServiceConsoleLogs",
    "AzureMetrics", "AzureNetworkingAnalytics", "NetworkSecurityGroupFlowCounter",
    "SecurityNodeIpData", "ThreatIntelIndicators", "OfficeActivity", "DeviceEvents",
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents",
    "DeviceLogonEvents", "DeviceImageLoadEvents", "AlertEvidence", "AlertInfo",
    "EmailEvents", "EmailUrlInfo", "EmailAttachmentInfo", "UrlClickEvents",
    "IdentityLogonEvents", "IdentityDirectoryEvents", "IdentityInputEvents",
    "CloudAppEvents", "AdvancedHunting-KQL", "AuditLogs", "SigninLogs",
    "AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs",
    "AWSCloudTrail", "GCPAuditLogs", "ThreatIntelIndicators",
    "Syslog", "CommonSecurityLog", "DnsEvents", "WireData",
    "WindowsEvent", "LinuxSyslog", "Event", "Perf", "Heartbeat",
    "ConfigurationChange", "ConfigurationData", "Update",
    "ContainerLog", "ContainerInventory", "ContainerNodeInventory",
    "KubeEvents", "KubePodInventory", "KubeNodeInventory", "KubeServices",
    "KubeEvents", "AzureDiagnostics", "AzureMetrics", "Activity",
    "InsightsMetrics", "InsightsDependency", "InsightsPulse",
    "BAT", "BIO", "BioDetection", "HealthState",
    "Watchlist", "WatchlistItems",
    "HuntingBookmark", "InvestigationNodes",
    "Usage", "VulnerabilityAssessment",
}

VALID_KQL_OPERATORS = {"|", "where", "summarize", "project", "extend", "join", "union",
                       "sort", "order", "top", "take", "limit", "count", "distinct",
                       "has_any", "has_all", "contains", "startswith", "endswith",
                       "matches", "regex", "in", "ago", "bin", "by", "and", "or",
                       "not", "isnull", "isnotnull", "isempty", "isnotempty",
                       "toupper", "tolower", "split", "strcat", "substring",
                       "todatetime", "tostring", "toint", "tolong", "toreal",
                       "iff", "case", "iif", "coalesce", "parse_json",
                       "make_list", "make_set", "dcount", "avg", "sum", "min", "max",
                       "percentile", "stdev", "variance", "arg_max", "arg_min"}

def validate_kql(query):
    """Validate KQL query basic syntax and table references."""
    issues = []
    
    if not query or query.strip() == "":
        issues.append("Empty query")
        return "WON'T-WORK", issues
    
    # Check for table name (first non-comment line)
    lines = [l.strip() for l in query.split("\n") if l.strip() and not l.strip().startswith("//")]
    if not lines:
        issues.append("No query content after comments")
        return "WON'T-WORK", issues
    
    first_line = lines[0]
    # Extract table name (first word that's not a comment)
    table_match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)', first_line)
    if not table_match:
        issues.append(f"No table name found in first line: {first_line[:80]}")
        return "NEEDS-REWRITE", issues
    
    table_name = table_match.group(1)
    if table_name not in VALID_TABLES:
        # Check if it's a known pattern we allow
        if table_name in ("let", "union", "with", "source", "datatable", "print"):
            # These are valid KQL starting keywords
            pass
        else:
            issues.append(f"Unknown/unverified table: {table_name}")
    
    # Check for basic KQL syntax
    has_pipe = "|" in query
    has_where = "where" in query.lower()
    
    if not has_pipe and not has_where:
        issues.append("No | or where clause — may not be valid KQL")
    
    # Check for string interpolation issues
    if "\\n" in query and not query.startswith("//"):
        # Newlines in query are fine for KQL
        pass
    
    # Check severity mapping
    return ("DEPLOY-AS-IS" if not issues else "NEEDS-TUNING"), issues


def severity_to_arm(severity_val, severity_label=None):
    """Convert severity to ARM template severity."""
    if severity_label:
        label = severity_label.upper()
        if label in ("HIGH",):
            return "High"
        elif label in ("MEDIUM",):
            return "Medium"
        elif label in ("LOW",):
            return "Low"
        elif label in ("INFORMATIONAL", "INFO"):
            return "Informational"
        elif label in ("CRITICAL",):
            return "High"  # ARM doesn't have Critical, maps to High
    
    if isinstance(severity_val, (int, float)):
        if severity_val >= 4:
            return "High"
        elif severity_val >= 3:
            return "Medium"
        elif severity_val >= 2:
            return "Medium"
        elif severity_val >= 1:
            return "Low"
        else:
            return "Informational"
    
    return "Medium"


def severity_to_oci(severity_val, severity_label=None):
    """Convert severity to OCI Cloud Guard severity."""
    if severity_label:
        label = severity_label.upper()
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


def rule_to_arm(rule):
    """Convert a single rule to an ARM template for Azure Sentinel."""
    rule_id = rule.get("rule_id", "UNKNOWN")
    name = rule.get("name", "Unnamed Rule")
    description = rule.get("description", "")
    query = rule.get("query", "")
    severity = severity_to_arm(rule.get("severity", 2), rule.get("severity_label"))
    
    # Map MITRE tactics to Sentinel-accepted format
    tactics = rule.get("tactics", [])
    # Normalize tactic names to Sentinel format (CamelCase)
    tactic_map = {
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "PrivilegeEscalation",
        "privilege_escalation": "PrivilegeEscalation",
        "defense-evasion": "DefenseEvasion",
        "defense_evasion": "DefenseEvasion",
        "credential-access": "CredentialAccess",
        "credential_access": "CredentialAccess",
        "discovery": "Discovery",
        "lateral-movement": "LateralMovement",
        "lateral_movement": "LateralMovement",
        "collection": "Collection",
        "command-and-control": "CommandAndControl",
        "command_and_control": "CommandAndControl",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
        "initial-access": "InitialAccess",
        "initial_access": "InitialAccess",
        "reconnaissance": "Reconnaissance",
        "resource-development": "ResourceDevelopment",
        "resource_development": "ResourceDevelopment",
        "credential_access": "CredentialAccess",
    }
    arm_tactics = []
    for t in tactics:
        arm_tactics.append(tactic_map.get(t.lower(), t))
    
    techniques = rule.get("mitre_attack", [])
    
    # Build frequency/period
    query_freq = rule.get("queryFrequency", "PT5H")
    query_period = rule.get("queryPeriod", "PT5H")
    trigger_op = rule.get("triggerOperator", "GreaterThan")
    trigger_threshold = rule.get("triggerThreshold", 0)
    
    arm_template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspaceName": {
                "type": "string",
                "defaultValue": "",
                "metadata": {"description": "The name of the Sentinel workspace"}
            },
            "location": {
                "type": "string",
                "defaultValue": "[resourceGroup().location]",
                "metadata": {"description": "Location for all resources"}
            }
        },
        "resources": [
            {
                "apiVersion": "2024-03-01",
                "type": "Microsoft.SecurityInsights/alertRules",
                "name": rule_id,
                "properties": {
                    "displayName": name,
                    "description": description,
                    "severity": severity,
                    "query": query,
                    "queryFrequency": query_freq,
                    "queryPeriod": query_period,
                    "triggerOperator": trigger_op,
                    "triggerThreshold": trigger_threshold,
                    "tactics": arm_tactics if arm_tactics else [],
                    "techniques": techniques if techniques else [],
                    "enabled": True,
                    "kind": "Scheduled"
                }
            }
        ],
        "outputs": {
            "ruleId": {
                "type": "string",
                "value": rule_id
            }
        }
    }
    
    # Add compliance info as tags if present
    compliance = rule.get("compliance", [])
    if compliance:
        arm_template["resources"][0]["properties"]["tags"] = {
            "compliance": ",".join(compliance)
        }
    
    return arm_template


def process_all_azure_rules():
    """Process all Azure rule files and generate ARM templates."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.json")))
    
    summary = {
        "platform": "azure",
        "total_files": len(files),
        "total_rules": 0,
        "by_status": {"DEPLOY-AS-IS": 0, "NEEDS-TUNING": 0, "NEEDS-REWRITE": 0, "WON'T-WORK": 0},
        "by_file": {}
    }
    
    for filepath in files:
        filename = os.path.basename(filepath)
        name_base = filename.replace(".json", "")
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        rules = data.get("rules", [])
        file_stats = {"total": len(rules), "DEPLOY-AS-IS": 0, "NEEDS-TUNING": 0,
                       "NEEDS-REWRITE": 0, "WON'T-WORK": 0}
        
        for rule in rules:
            rule_id = rule.get("rule_id", f"AZ-UNKNOWN-{summary['total_rules']}")
            query = rule.get("query", "")
            
            status, issues = validate_kql(query)
            
            file_stats[status] += 1
            summary["by_status"][status] += 1
            summary["total_rules"] += 1
            
            if status in ("DEPLOY-AS-IS", "NEEDS-TUNING"):
                arm = rule_to_arm(rule)
                if status == "NEEDS-TUNING":
                    arm["resources"][0]["properties"]["description"] += f"\n\n⚠️ NEEDS-TUNING: {'; '.join(issues)}"
                
                out_file = os.path.join(OUTPUT_DIR, f"{rule_id}_arm.json")
                with open(out_file, 'w') as f:
                    json.dump(arm, f, indent=2)
            
            elif status == "NEEDS-REWRITE":
                # Write the issue documentation
                rewrites_dir = os.path.join(OUTPUT_DIR, "rewrites")
                os.makedirs(rewrites_dir, exist_ok=True)
                issue_file = os.path.join(rewrites_dir, f"{rule_id}_issues.md")
                with open(issue_file, 'w') as f:
                    f.write(f"# {rule_id} — {rule.get('name', 'Unknown')}\n\n")
                    f.write(f"**Status:** NEEDS-REWRITE\n\n")
                    f.write(f"**Issues:**\n")
                    for issue in issues:
                        f.write(f"- {issue}\n")
                    f.write(f"\n**Original Query:**\n```\n{query}\n```\n")
        
        summary["by_file"][filename] = file_stats
    
    with open(SUMMARY_FILE, 'w') as f:
        json.dump(summary, f, indent=2)
    
    return summary


if __name__ == "__main__":
    print("Converting Azure SIEM rules to ARM templates...")
    summary = process_all_azure_rules()
    print(f"\nDone! {summary['total_rules']} rules processed across {summary['total_files']} files")
    print(f"  DEPLOY-AS-IS:   {summary['by_status']['DEPLOY-AS-IS']}")
    print(f"  NEEDS-TUNING:   {summary['by_status']['NEEDS-TUNING']}")
    print(f"  NEEDS-REWRITE:  {summary['by_status']['NEEDS-REWRITE']}")
    wont = summary['by_status']['WON\'T-WORK']
    print(f"  WON'T-WORK:     {wont}")
    print(f"\nARM templates: {OUTPUT_DIR}")
    print(f"Summary: {SUMMARY_FILE}")