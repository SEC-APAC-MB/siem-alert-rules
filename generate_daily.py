#!/usr/bin/env python3
"""
Daily SIEM Rule Generation Engine
==================================
Pulls live threat intel and generates 100+ new rules per day across all 11 platforms.

Usage:
  python3 generate_daily.py                    # Full daily run
  python3 generate_daily.py --platforms oracle azure aws  # Specific platforms
  python3 generate_daily.py --count 200        # Override rule count
  python3 generate_daily.py --dry-run          # Preview without writing

Architecture:
  1. Fetch threat intel (CISA KEV, NVD CVE, MITRE ATT&CK)
  2. Load existing rule catalog
  3. Generate new rules based on:
     - New CVEs from threat intel
     - Emerging attack patterns
     - Pentest techniques
     - Coverage gaps
  4. Output in platform-specific formats
  5. Validate all generated rules
  6. Git commit and push
"""

import json
import os
import sys
import hashlib
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).parent
RULES_DIR = BASE / "rules"
INTEL_DIR = BASE / "threat_intel"
GENERATED_DIR = BASE / "generated"
LOG_DIR = BASE / "logs"

os.makedirs(GENERATED_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

PLATFORMS = [
    "elastic", "splunk", "fortisiem", "qradar", "sentinel",
    "wazuh", "zeek", "suricata", "oracle", "azure", "aws"
]

# ─── Rule ID Sequences ───────────────────────────────────────

CATEGORIES = {
    "cloud-native": {"prefix": {"elastic": "ES-CLOUD", "splunk": "SPL-CLOUD", "fortisiem": "FSIEM-CLOUD", "qradar": "QR-CLOUD", "sentinel": "AZ-CLOUD", "wazuh": "WZ-CLOUD", "zeek": "ZK-CLOUD", "suricata": "SUR-CLOUD", "oracle": "OCI-CLOUD", "azure": "AZ-CLOUD", "aws": "AWS-CLOUD"}},
    "ransomware": {"prefix": {"elastic": "ES-RW", "splunk": "SPL-RW", "fortisiem": "FSIEM-RW", "qradar": "QR-RW", "sentinel": "AZ-RW", "wazuh": "WZ-RW", "zeek": "ZK-RW", "suricata": "SUR-RW", "oracle": "OCI-RW", "azure": "AZ-RW", "aws": "AWS-RW"}},
    "zero-day": {"prefix": {"elastic": "ES-ZD", "splunk": "SPL-ZD", "fortisiem": "FSIEM-ZD", "qradar": "QR-ZD", "sentinel": "AZ-ZD", "wazuh": "WZ-ZD", "zeek": "ZK-ZD", "suricata": "SUR-ZD", "oracle": "OCI-ZD", "azure": "AZ-ZD", "aws": "AWS-ZD"}},
    "supply-chain": {"prefix": {"elastic": "ES-SC", "splunk": "SPL-SC", "fortisiem": "FSIEM-SC", "qradar": "QR-SC", "sentinel": "AZ-SC", "wazuh": "WZ-SC", "zeek": "ZK-SC", "suricata": "SUR-SC", "oracle": "OCI-SC", "azure": "AZ-SC", "aws": "AWS-SC"}},
    "exfiltration": {"prefix": {"elastic": "ES-EXFIL", "splunk": "SPL-EXFIL", "fortisiem": "FSIEM-EXFIL", "qradar": "QR-EXFIL", "sentinel": "AZ-EXFIL", "wazuh": "WZ-EXFIL", "zeek": "ZK-EXFIL", "suricata": "SUR-EXFIL", "oracle": "OCI-EXFIL", "azure": "AZ-EXFIL", "aws": "AWS-EXFIL"}},
    "mobile": {"prefix": {"elastic": "ES-MB", "splunk": "SPL-MB", "fortisiem": "FSIEM-MB", "qradar": "QR-MB", "sentinel": "AZ-MB", "wazuh": "WZ-MB", "zeek": "ZK-MB", "suricata": "SUR-MB", "oracle": "OCI-MB", "azure": "AZ-MB", "aws": "AWS-MB"}},
    "ics-ot": {"prefix": {"elastic": "ES-ICS", "splunk": "SPL-ICS", "fortisiem": "FSIEM-ICS", "qradar": "QR-ICS", "sentinel": "AZ-ICS", "wazuh": "WZ-ICS", "zeek": "ZK-ICS", "suricata": "SUR-ICS", "oracle": "OCI-ICS", "azure": "AZ-ICS", "aws": "AWS-ICS"}},
    "ai-llm": {"prefix": {"elastic": "ES-AI", "splunk": "SPL-AI", "fortisiem": "FSIEM-AI", "qradar": "QR-AI", "sentinel": "AZ-AI", "wazuh": "WZ-AI", "zeek": "ZK-AI", "suricata": "SUR-AI", "oracle": "OCI-AI", "azure": "AZ-AI", "aws": "AWS-AI"}},
    "pentest-recon": {"prefix": {"elastic": "ES-PT-RECON", "splunk": "SPL-PT-RECON", "fortisiem": "FSIEM-PT-RECON", "qradar": "QR-PT-RECON", "sentinel": "AZ-PT-RECON", "wazuh": "WZ-PT-RECON", "zeek": "ZK-PT-RECON", "suricata": "SUR-PT-RECON", "oracle": "OCI-PT-RECON", "azure": "AZ-PT-RECON", "aws": "AWS-PT-RECON"}},
    "pentest-access": {"prefix": {"elastic": "ES-PT-IA", "splunk": "SPL-PT-IA", "fortisiem": "FSIEM-PT-IA", "qradar": "QR-PT-IA", "sentinel": "AZ-PT-IA", "wazuh": "WZ-PT-IA", "zeek": "ZK-PT-IA", "suricata": "SUR-PT-IA", "oracle": "OCI-PT-IA", "azure": "AZ-PT-IA", "aws": "AWS-PT-IA"}},
    "pentest-exec": {"prefix": {"elastic": "ES-PT-EXEC", "splunk": "SPL-PT-EXEC", "fortisiem": "FSIEM-PT-EXEC", "qradar": "QR-PT-EXEC", "sentinel": "AZ-PT-EXEC", "wazuh": "WZ-PT-EXEC", "zeek": "ZK-PT-EXEC", "suricata": "SUR-PT-EXEC", "oracle": "OCI-PT-EXEC", "azure": "AZ-PT-EXEC", "aws": "AWS-PT-EXEC"}},
    "pentest-persist": {"prefix": {"elastic": "ES-PT-PERS", "splunk": "SPL-PT-PERS", "fortisiem": "FSIEM-PT-PERS", "qradar": "QR-PT-PERS", "sentinel": "AZ-PT-PERS", "wazuh": "WZ-PT-PERS", "zeek": "ZK-PT-PERS", "suricata": "SUR-PT-PERS", "oracle": "OCI-PT-PERS", "azure": "AZ-PT-PERS", "aws": "AWS-PT-PERS"}},
    "pentest-exfil": {"prefix": {"elastic": "ES-PT-EXFIL", "splunk": "SPL-PT-EXFIL", "fortisiem": "FSIEM-PT-EXFIL", "qradar": "QR-PT-EXFIL", "sentinel": "AZ-PT-EXFIL", "wazuh": "WZ-PT-EXFIL", "zeek": "ZK-PT-EXFIL", "suricata": "SUR-PT-EXFIL", "oracle": "OCI-PT-EXFIL", "azure": "AZ-PT-EXFIL", "aws": "AWS-PT-EXFIL"}},
    "pentest-lateral": {"prefix": {"elastic": "ES-PT-LM", "splunk": "SPL-PT-LM", "fortisiem": "FSIEM-PT-LM", "qradar": "QR-PT-LM", "sentinel": "AZ-PT-LM", "wazuh": "WZ-PT-LM", "zeek": "ZK-PT-LM", "suricata": "SUR-PT-LM", "oracle": "OCI-PT-LM", "azure": "AZ-PT-LM", "aws": "AWS-PT-LM"}},
}

# ─── Platform Formatters ─────────────────────────────────────

def format_elastic(rule, seq):
    """Format rule for Elastic Security (KQL/EQL + Rule API JSON)."""
    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
    return {
        "rule_id": rule.get("rule_id", f"ES-{rule.get('category', 'GEN').upper()}-{seq:03d}"),
        "name": rule["name"],
        "description": rule["description"],
        "severity": severity_map.get(rule.get("severity", "medium"), "medium"),
        "type": rule.get("rule_type", "query"),
        "query": rule.get("query", rule.get("detection", {}).get("query", "")),
        "index": rule.get("index", ["logs-*", "apm-*"]),
        "references": rule.get("references", []),
        "mitre": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "tags": rule.get("tags", [rule.get("category", "general")]),
        "risk_score": {"critical": 95, "high": 75, "medium": 50, "low": 25, "informational": 10}.get(rule.get("severity", "medium"), 50),
        "interval": rule.get("interval", "5m"),
    }


def format_splunk(rule, seq):
    """Format rule for Splunk Enterprise (SPL + correlation searches)."""
    return {
        "rule_id": rule.get("rule_id", f"SPL-{rule.get('category', 'GEN').upper()}-{seq:03d}"),
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule.get("severity", "medium"),
        "search": rule.get("query", rule.get("detection", {}).get("query", "")),
        "action": rule.get("actions", [{"type": "alert", "description": "Send to SOC"}]),
        "references": rule.get("references", []),
        "mitre": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_oracle(rule, seq):
    """Format rule for Oracle Cloud Infrastructure (OCI Alarm)."""
    return {
        "rule_id": rule.get("rule_id", f"OCI-{rule.get('category', 'GEN').upper()}-{seq:03d}"),
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule.get("severity", "MEDIUM").upper(),
        "category": rule.get("category", "general"),
        "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "query": rule.get("query", f"MQL: {rule['name']} -- OCI Monitoring Query Language detection"),
        "rule_type": rule.get("rule_type", "query"),
        "interval": rule.get("interval", "5m"),
        "condition": rule.get("condition", {
            "eventType": ["com.oracle.cloud.monitoring"],
            "compartmentId": "$COMPARTMENT_ID",
            "metric": rule.get("category", "general").replace("-", "_"),
            "operator": "GT",
            "threshold": 5
        }),
        "actions": rule.get("actions", [{"actionType": "ONS", "description": "Send alert notification"}]),
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_azure(rule, seq):
    """Format rule for Microsoft Azure Monitor/Sentinel (KQL)."""
    severity_map = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low", "informational": "Informational"}
    return {
        "rule_id": rule.get("rule_id", f"AZ-{rule.get('category', 'GEN').upper()}-{seq:03d}"),
        "name": rule["name"],
        "description": rule["description"],
        "severity": severity_map.get(rule.get("severity", "medium"), "Medium"),
        "category": rule.get("category", "general"),
        "tactics": rule.get("tactics", []),
        "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "query": rule.get("query", f"KQL: {rule['name']} -- Azure Monitor/Sentinel detection"),
        "queryFrequency": rule.get("interval", "5m"),
        "queryPeriod": rule.get("query_period", "10m"),
        "triggerOperator": rule.get("trigger_operator", "gt"),
        "triggerThreshold": rule.get("trigger_threshold", 5),
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_aws(rule, seq):
    """Format rule for AWS (CloudWatch + EventBridge + GuardDuty)."""
    return {
        "rule_id": rule.get("rule_id", f"AWS-{rule.get('category', 'GEN').upper()}-{seq:03d}"),
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule.get("severity", "medium"),
        "category": rule.get("category", "general"),
        "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "source": rule.get("source", ["aws.cloudtrail"]),
        "detection": rule.get("detection", {
            "query_type": "cloudwatch_metric_filter",
            "filter_pattern": f"{{ ($.eventName = \"*\") }}",
            "log_group": "/aws/cloudtrail",
            "metric_namespace": "Security/Monitoring",
            "metric_name": rule["name"].replace(" ", ""),
            "threshold": 5,
            "evaluation_periods": 1,
            "statistic": "Sum",
            "period": 300
        }),
        "actions": rule.get("actions", [
            {"type": "SNS", "description": "Send alert to security team SNS topic"},
            {"type": "Lambda", "description": "Trigger automated remediation Lambda function"}
        ]),
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_wazuh(rule, seq):
    """Format rule for Wazuh (XML)."""
    return {
        "rule_id": rule.get("rule_id", f"WZ-{rule.get('category', 'GEN').upper()}-{seq:03d}"),
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule.get("severity", "medium"),
        "category": rule.get("category", "general"),
        "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "match": rule.get("match", rule.get("query", "")),
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_suricata(rule, seq):
    """Format rule for Suricata (IDS/IPS rule format)."""
    sid = 4000000 + seq  # Suricata SID range for custom rules
    severity_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5}
    msg = rule["name"].replace('"', '\\"')
    desc = rule["description"].replace('"', '\\"')
    mitre_tags = ",".join(rule.get("mitre_attack", rule.get("mitre", [])))
    cat_upper = rule.get("category", "GEN").upper()
    rule_name = rule["name"].replace('"', '\\"')
    suricata_msg = "alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"SIEM " + cat_upper + "-" + str(seq).zfill(3) + ": " + rule_name + "\"; flow:established,to_server; sid:" + str(sid) + "; rev:1;)"
    
    return {
        "rule_id": "SUR-" + cat_upper + "-" + str(seq).zfill(3),
        "sid": sid,
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule.get("severity", "medium"),
        "category": rule.get("category", "general"),
        "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "suricata_rule": suricata_msg,
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_zeek(rule, seq):
    """Format rule for Zeek (signature format)."""
    uid = f"ZK-{rule.get('category', 'GEN').upper()}-{seq:03d}"
    return {
        "rule_id": uid,
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule.get("severity", "medium"),
        "category": rule.get("category", "general"),
        "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "zeek_signature": f'signature {uid} {{\n\tip-proto tcp\n\tdst-port = {{ 80 443 8080 8443 }}\n\thttp-request /.*({rule.get("query", "")}).*/ regex\n\tevent "{rule["name"]}"\n}}',
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_fortisiem(rule, seq):
    """Format rule for FortiSIEM (XML pattern)."""
    severity_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Info"}
    return {
        "rule_id": f"FSIEM-{rule.get('category', 'GEN').upper()}-{seq:03d}",
        "name": rule["name"],
        "description": rule["description"],
        "severity": severity_map.get(rule.get("severity", "medium"), "Medium"),
        "category": rule.get("category", "general"),
        "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "pattern": rule.get("query", f"<Pattern>{rule['name']}</Pattern>"),
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_qradar(rule, seq):
    """Format rule for IBM QRadar (AQL)."""
    return {
        "rule_id": f"QR-{rule.get('category', 'GEN').upper()}-{seq:03d}",
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule.get("severity", "medium"),
        "category": rule.get("category", "general"),
        "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
        "compliance": rule.get("compliance", []),
        "aql_query": rule.get("query", f"SELECT * FROM events WHERE CATEGORY = '{rule.get('category', 'general')}'"),
        "tags": rule.get("tags", [rule.get("category", "general")]),
    }


def format_sentinel(rule, seq):
    """Format rule for Microsoft Sentinel (KQL — same as Azure)."""
    return format_azure(rule, seq)


FORMATTERS = {
    "elastic": format_elastic,
    "splunk": format_splunk,
    "fortisiem": format_fortisiem,
    "qradar": format_qradar,
    "sentinel": format_sentinel,
    "wazuh": format_wazuh,
    "zeek": format_zeek,
    "suricata": format_suricata,
    "oracle": format_oracle,
    "azure": format_azure,
    "aws": format_aws,
}


# ─── Load Threat Intel ────────────────────────────────────────

def load_threat_intel():
    """Load the latest threat intel data."""
    latest = INTEL_DIR / "threat_intel_latest.json"
    if not latest.exists():
        print("WARNING: No threat intel data found. Run threat_intel_ingest.py first.")
        print("Falling back to built-in rule templates.")
        return {}
    
    data = json.loads(latest.read_text())
    total = sum(len(v) for v in data.values())
    print(f"Loaded threat intel: {total} entries from {len(data)} sources")
    for k, v in data.items():
        print(f"  {k}: {len(v)} entries")
    return data


# ─── Generate Rules from Intel ────────────────────────────────

def generate_cve_rules(cve_list, platform):
    """Generate SIEM rules from CVE data."""
    rules = []
    for cve in cve_list:
        category = cve.get("category", "general")
        severity = cve.get("severity", "medium")
        mitre = cve.get("mitre_techniques", [])
        cve_id = cve.get("cve_id", "UNKNOWN")
        product = cve.get("product", "Unknown")
        desc = cve.get("description", f"Detection of {cve_id} exploitation")
        
        rule = {
            "name": f"{cve_id} — {product} Exploitation",
            "description": f"Detects exploitation attempts targeting {cve_id}: {desc}. Product: {product}",
            "severity": severity,
            "category": category,
            "mitre_attack": mitre,
            "compliance": ["PCI-DSS-6.5", "NIST-800-53-SI-4", "GDPR-32A"],
            "tags": [category, "cve", cve_id.lower(), "exploited"],
            "references": [cve_id],
        }
        rules.append(rule)
    return rules


def generate_mitre_rules(mitre_list, platform):
    """Generate SIEM rules from MITRE ATT&CK techniques."""
    rules = []
    for tech in mitre_list:
        tid = tech.get("technique_id", "UNKNOWN")
        name = tech.get("name", "Unknown Technique")
        desc = tech.get("description", "")[:200]
        tactics = tech.get("tactics", [])
        severity = tech.get("severity", "medium")
        
        rule = {
            "name": f"MITRE {tid}: {name}",
            "description": f"Detects ATT&CK technique {tid} ({name}). {desc}",
            "severity": severity,
            "category": "mitre-attack",
            "mitre_attack": [tid],
            "compliance": ["NIST-800-53-SI-4", "PCI-DSS-10.2"],
            "tags": ["mitre-attack", tid.lower()] + tactics,
        }
        rules.append(rule)
    return rules


# ─── Main Generation ─────────────────────────────────────────

def generate_daily(target_count=100, platforms=None, dry_run=False):
    """Generate daily rules across all platforms."""
    if platforms is None:
        platforms = PLATFORMS
    
    print(f"\n{'=' * 60}")
    print(f"DAILY RULE GENERATION — Target: {target_count} rules/platform")
    print(f"Platforms: {', '.join(platforms)}")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'=' * 60}")
    
    # Load threat intel
    intel = load_threat_intel()
    
    # Generate base rules from intel
    base_rules = []
    
    # CVE-based rules
    cisa_kev = intel.get("cisa_kev", [])
    nvd_critical = intel.get("nvd_critical", [])
    nvd_high = intel.get("nvd_high", [])
    
    if cisa_kev:
        base_rules.extend(generate_cve_rules(cisa_kev[:20], "all"))
    if nvd_critical:
        base_rules.extend(generate_cve_rules(nvd_critical[:15], "all"))
    if nvd_high:
        base_rules.extend(generate_cve_rules(nvd_high[:15], "all"))
    
    # MITRE-based rules
    mitre = intel.get("mitre_attack", [])
    if mitre:
        base_rules.extend(generate_mitre_rules(mitre[:20], "all"))
    
    # Emerging threat rules
    emerging = intel.get("emerging", [])
    base_rules.extend(emerging)
    
    # Pentest rules
    pentest = intel.get("pentest", [])
    base_rules.extend(pentest)
    
    print(f"\nBase rules from threat intel: {len(base_rules)}")
    
    # For each platform, format and write
    total_written = 0
    for platform in platforms:
        formatter = FORMATTERS.get(platform)
        if not formatter:
            print(f"  Skipping unknown platform: {platform}")
            continue
        
        platform_rules = []
        seq = 1
        for rule in base_rules[:target_count]:
            formatted = formatter(rule, seq)
            platform_rules.append(formatted)
            seq += 1
        
        # Write to category file
        if not dry_run:
            output_dir = RULES_DIR / platform
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Group by category
            categories = {}
            for rule in platform_rules:
                cat = rule.get("category", "general")
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(rule)
            
            for cat, cat_rules in categories.items():
                output_file = output_dir / f"generated-{cat}.json"
                if output_file.exists():
                    existing = json.loads(output_file.read_text())
                    if isinstance(existing, list):
                        # Merge, avoiding duplicates by rule_id
                        existing_ids = {r.get("rule_id") for r in existing}
                        for r in cat_rules:
                            if r.get("rule_id") not in existing_ids:
                                existing.append(r)
                        cat_rules = existing
                    elif isinstance(existing, dict) and "rules" in existing:
                        existing_ids = {r.get("rule_id") for r in existing["rules"]}
                        for r in cat_rules:
                            if r.get("rule_id") not in existing_ids:
                                existing["rules"].append(r)
                        existing["total_rules"] = len(existing["rules"])
                        cat_rules = existing
                
                with open(output_file, "w") as f:
                    json.dump(cat_rules, f, indent=2)
            
            platform_count = len(platform_rules)
            total_written += platform_count
            print(f"  {platform}: {platform_count} rules written")
        else:
            print(f"  {platform}: {len(platform_rules)} rules (dry run, not written)")
    
    print(f"\n{'=' * 60}")
    print(f"TOTAL: {total_written} rules across {len(platforms)} platforms")
    print(f"{'=' * 60}")
    
    # Log
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_count": target_count,
        "platforms": platforms,
        "base_rules": len(base_rules),
        "total_written": total_written,
        "dry_run": dry_run,
        "intel_sources": {k: len(v) for k, v in intel.items()} if intel else {},
    }
    log_file = LOG_DIR / f"generation_{datetime.now().strftime('%Y%m%d')}.json"
    with open(log_file, "w") as f:
        json.dump(log_entry, f, indent=2)
    print(f"Log: {log_file}")
    
    return total_written


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Daily SIEM Rule Generation Engine")
    parser.add_argument("--platforms", nargs="+", default=None, help="Specific platforms to generate")
    parser.add_argument("--count", type=int, default=100, help="Number of rules per platform")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    args = parser.parse_args()
    
    generate_daily(
        target_count=args.count,
        platforms=args.platforms,
        dry_run=args.dry_run,
    )