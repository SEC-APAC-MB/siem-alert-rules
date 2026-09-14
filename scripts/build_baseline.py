#!/usr/bin/env python3
"""Build minimum baseline rule sets for Oracle and Azure."""
import json, glob, os
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).parent.parent

# Minimum baseline categories — the essential 10 domains
BASELINE_CATEGORIES = [
    "initial_access",
    "privilege-escalation", 
    "privilege_escalation",
    "lateral_movement",
    "lateral-movement",
    "exfiltration",
    "persistence",
    "ransomware",
    "reconnaissance",
    "database",
    "supply_chain",
    "zero_day",
    "sql-injection",
    "sql_injection",
    "ssrf",
    "remote-code-execution",
    "execution",
]

# Map categories to baseline domains for documentation
BASELINE_DOMAINS = {
    "initial_access": {"name": "Authentication & Initial Access", "description": "Brute force, failed logins, external access attempts", "weight": "critical"},
    "privilege_escalation": {"name": "Privilege Escalation", "description": "Admin role changes, policy modifications, unauthorized elevation", "weight": "critical"},
    "lateral_movement": {"name": "Lateral Movement", "description": "Internal SSH/RDP, process execution across hosts", "weight": "high"},
    "exfiltration": {"name": "Data Exfiltration", "description": "Large data transfers, unusual outbound traffic", "weight": "high"},
    "persistence": {"name": "Persistence", "description": "New user creation, API keys, scheduled tasks, backdoors", "weight": "high"},
    "ransomware": {"name": "Ransomware Detection", "description": "Mass file encryption, storage spikes, ransom indicators", "weight": "critical"},
    "reconnaissance": {"name": "Reconnaissance & Scanning", "description": "Port scans, dropped connections, service enumeration", "weight": "medium"},
    "database": {"name": "Database Security", "description": "SQL injection, failed connections, unauthorized queries", "weight": "high"},
    "supply_chain": {"name": "Supply Chain Security", "description": "Image tampering, unauthorized deployments, dependency attacks", "weight": "high"},
    "zero_day": {"name": "Zero-Day & Anomalous Activity", "description": "Unexpected ports, anomalous patterns, novel exploits", "weight": "critical"},
    "sql_injection": {"name": "SQL Injection", "description": "Injection patterns, union selects, OR 1=1 attempts", "weight": "high"},
    "ssrf": {"name": "Server-Side Request Forgery", "description": "Internal IP access, metadata endpoint queries", "weight": "high"},
    "remote_code_execution": {"name": "Remote Code Execution", "description": "Code execution exploits, CVE-based RCE attempts", "weight": "critical"},
    "execution": {"name": "Execution & Process Activity", "description": "PowerShell abuse, suspicious process creation", "weight": "high"},
}

def collect_baseline_rules(platform):
    """Collect baseline rules from essential categories."""
    rules_by_cat = {}
    all_baseline = []
    
    for f in sorted(glob.glob(str(BASE / "rules" / platform / "*.json"))):
        with open(f) as fh:
            data = json.load(fh)
        rules = data.get("rules", []) if isinstance(data, dict) else data
        
        for r in rules:
            cat = (r.get("category", "") or "").lower().replace("-", "_")
            
            if cat in BASELINE_CATEGORIES:
                # Deduplicate by rule_id
                rid = r.get("rule_id", "")
                if rid and rid not in [x.get("rule_id") for x in all_baseline]:
                    all_baseline.append(r)
                    if cat not in rules_by_cat:
                        rules_by_cat[cat] = []
                    rules_by_cat[cat].append(r)
    
    return all_baseline, rules_by_cat

def build_baseline_package(platform):
    """Build the minimum baseline package for a platform."""
    rules, by_cat = collect_baseline_rules(platform)
    
    pkg_dir = BASE / "deployments" / "baseline" / platform
    pkg_dir.mkdir(parents=True, exist_ok=True)
    
    # Group rules by domain
    domains = []
    seen_cats = set()
    
    for cat_key, domain_info in BASELINE_DOMAINS.items():
        cat_rules = by_cat.get(cat_key, [])
        if not cat_rules:
            # Try with dashes
            cat_dash = cat_key.replace("_", "-")
            cat_rules = by_cat.get(cat_dash, [])
        
        if cat_rules:
            seen_cats.add(cat_key)
            domains.append({
                "domain": domain_info["name"],
                "category": cat_key,
                "weight": domain_info["weight"],
                "description": domain_info["description"],
                "rule_count": len(cat_rules),
                "rule_ids": [r["rule_id"] for r in cat_rules[:10]],  # Sample
            })
    
    # Write baseline rules bundle
    bundle = {
        "description": f"Minimum Baseline SIEM Rules — {platform.upper()}",
        "version": "1.0.0",
        "type": "minimum-baseline",
        "generated": datetime.now(timezone.utc).isoformat(),
        "total_rules": len(rules),
        "domains_covered": len(domains),
        "domains": domains,
        "rules": rules,
    }
    
    with open(pkg_dir / "baseline-rules.json", "w") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
    
    # Write compliance mapping
    compliance = {
        "description": "Minimum baseline compliance mapping",
        "frameworks": ["NIS2", "DORA", "PCI-DSS", "GDPR", "NIST-800-53"],
        "coverage": [],
    }
    
    framework_map = {
        "NIS2": {"initial_access": "Art. 15(1)", "privilege_escalation": "Art. 15(1)", "lateral_movement": "Art. 15(1)", "exfiltration": "Art. 15(1)", "persistence": "Art. 15(1)", "ransomware": "Art. 15(1)", "reconnaissance": "Art. 15(1)", "database": "Art. 15(1)", "supply_chain": "Art. 15(1)(e)", "zero_day": "Art. 15(1)", "sql_injection": "Art. 15(1)", "ssrf": "Art. 15(1)", "remote_code_execution": "Art. 15(1)", "execution": "Art. 15(1)"},
        "DORA": {"initial_access": "Art. 7(a)", "privilege_escalation": "Art. 6(d)", "lateral_movement": "Art. 8(a)", "exfiltration": "Art. 7(d)", "persistence": "Art. 7(b)", "ransomware": "Art. 9", "reconnaissance": "Art. 8(a)", "database": "Art. 7(a)", "supply_chain": "Art. 28", "zero_day": "Art. 8(a)", "sql_injection": "Art. 7(a)", "ssrf": "Art. 7(a)", "remote_code_execution": "Art. 8(a)", "execution": "Art. 8(a)"},
        "PCI-DSS": {"initial_access": "Req. 8", "privilege_escalation": "Req. 7", "lateral_movement": "Req. 10", "exfiltration": "Req. 12", "persistence": "Req. 10", "ransomware": "Req. 12", "reconnaissance": "Req. 11", "database": "Req. 6", "supply_chain": "Req. 12", "zero_day": "Req. 6", "sql_injection": "Req. 6.5", "ssrf": "Req. 6.5", "remote_code_execution": "Req. 6.5", "execution": "Req. 10"},
        "GDPR": {"initial_access": "Art. 32", "privilege_escalation": "Art. 32", "lateral_movement": "Art. 32", "exfiltration": "Art. 33", "persistence": "Art. 32", "ransomware": "Art. 33", "reconnaissance": "Art. 32", "database": "Art. 32", "supply_chain": "Art. 32", "zero_day": "Art. 32", "sql_injection": "Art. 32", "ssrf": "Art. 32", "remote_code_execution": "Art. 32", "execution": "Art. 32"},
        "NIST-800-53": {"initial_access": "IA-2, AC-7", "privilege_escalation": "AC-6, AU-9", "lateral_movement": "AC-4, SC-7", "exfiltration": "AC-4, SC-8", "persistence": "CM-7, AC-3", "ransomware": "CP-9, SI-4", "reconnaissance": "SI-4, SC-7", "database": "SI-10, SC-13", "supply_chain": "SR-3, SA-12", "zero_day": "SI-4, SI-3", "sql_injection": "SI-10", "ssrf": "SI-10", "remote_code_execution": "SI-3, SC-5", "execution": "AU-12, CM-7"},
    }
    
    for fw, controls in framework_map.items():
        fw_domains = []
        for cat_key, domain_info in BASELINE_DOMAINS.items():
            if cat_key in seen_cats:
                control = controls.get(cat_key, "")
                cat_rules = by_cat.get(cat_key, by_cat.get(cat_key.replace("_", "-"), []))
                if cat_rules:
                    fw_domains.append({
                        "domain": domain_info["name"],
                        "control": control,
                        "rule_count": len(cat_rules),
                    })
        compliance["coverage"].append({"framework": fw, "domains": fw_domains})
    
    with open(pkg_dir / "compliance-mapping.json", "w") as f:
        json.dump(compliance, f, indent=2, ensure_ascii=False)
    
    # Write deployment config
    if platform == "oracle":
        config = """# Minimum Baseline — Oracle OCI Configuration
compartment_id: "ocid1.compartment.oc1..XXXXX"
region: "eu-frankfurt-1"
tenancy_id: "ocid1.tenancy.oc1..XXXXX"
notification_topic_id: "ocid1.onstopic.oc1..XXXXX"
"""
    else:
        config = """# Minimum Baseline — Microsoft Azure Configuration
subscription_id: "XXXXX-XXXXX-XXXXX-XXXXX"
resource_group: "security-siem"
workspace_name: "security-log-analytics"
location: "westeurope"
"""
    with open(pkg_dir / "deployment-config.yaml", "w") as f:
        f.write(config)
    
    # Write deploy script
    if platform == "oracle":
        deploy = '''#!/bin/bash
# Minimum Baseline — Oracle OCI Deployment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES_FILE="$SCRIPT_DIR/baseline-rules.json"
CONFIG_FILE="$SCRIPT_DIR/deployment-config.yaml"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --config) CONFIG_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--config <file>]"
            echo ""
            echo "Deploys minimum baseline SIEM rules to Oracle OCI."
            echo "Baseline covers: initial access, privilege escalation, lateral movement,"
            echo "exfiltration, persistence, ransomware, reconnaissance, database, supply chain,"
            echo "zero-day, SQL injection, SSRF, RCE, and execution."
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== Minimum Baseline — Oracle OCI ==="
echo ""

if ! command -v oci &>/dev/null; then
    echo "ERROR: OCI CLI not installed."
    exit 1
fi

COMPARTMENT_ID=$(grep "compartment_id:" "$CONFIG_FILE" | head -1 | sed 's/.*: *"//' | sed 's/".*//')
REGION=$(grep "region:" "$CONFIG_FILE" | head -1 | sed 's/.*: *"//' | sed 's/".*//')

echo "Compartment: $COMPARTMENT_ID"
echo "Region: $REGION"
echo ""

TOTAL=$(python3 -c "import json; print(len(json.load(open('$RULES_FILE')).get('rules',[])))")
echo "Baseline rules to deploy: $TOTAL"
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "=== DRY RUN ==="
    python3 -c "
import json
with open('$RULES_FILE') as f:
    data = json.load(f)
for d in data.get('domains', []):
    print(f\"  [{d['weight'].upper()}] {d['domain']}: {d['rule_count']} rules\")
print(f\"\\nTotal: {data['total_rules']} rules across {data['domains_covered']} domains\")
"
    exit 0
fi

python3 -c "
import json, subprocess, sys
with open('$RULES_FILE') as f:
    data = json.load(f)
rules = data.get('rules', [])
success = 0
failed = 0
for r in rules:
    try:
        cmd = ['oci', 'monitoring', 'alarm', 'create',
            '--display-name', r['rule_id'][:100],
            '--compartment-id', '$COMPARTMENT_ID',
            '--metric-compartment-id', '$COMPARTMENT_ID',
            '--namespace', 'oci_logging',
            '--query-text', r.get('query', ''),
            '--severity', r.get('severity', 'MEDIUM').lower(),
            '--pending-duration', 'PT5M',
            '--body', r.get('description', r.get('name', ''))[:500],
            '--is-enabled', 'true', '--output', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f\"  OK {r['rule_id']}\")
            success += 1
        else:
            print(f\"  FAIL {r['rule_id']}: {result.stderr[:80]}\")
            failed += 1
    except Exception as e:
        print(f\"  FAIL {r['rule_id']}: {e}\")
        failed += 1
print(f\"\\nDeployed: {success} | Failed: {failed} | Total: {success+failed}\")
sys.exit(0 if failed == 0 else 1)
"
'''
    else:
        deploy = '''#!/bin/bash
# Minimum Baseline — Microsoft Azure Deployment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES_FILE="$SCRIPT_DIR/baseline-rules.json"
CONFIG_FILE="$SCRIPT_DIR/deployment-config.yaml"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --config) CONFIG_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--config <file>]"
            echo ""
            echo "Deploys minimum baseline SIEM rules to Microsoft Sentinel."
            echo "Baseline covers: initial access, privilege escalation, lateral movement,"
            echo "exfiltration, persistence, ransomware, reconnaissance, database, supply chain,"
            echo "zero-day, SQL injection, SSRF, RCE, and execution."
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== Minimum Baseline — Microsoft Azure ==="
echo ""

if ! command -v az &>/dev/null; then
    echo "ERROR: Azure CLI not installed."
    exit 1
fi

if ! az account show &>/dev/null; then
    echo "ERROR: Not authenticated. Run: az login"
    exit 1
fi

SUBSCRIPTION_ID=$(grep "subscription_id:" "$CONFIG_FILE" | head -1 | sed 's/.*: *"//' | sed 's/".*//')
RESOURCE_GROUP=$(grep "resource_group:" "$CONFIG_FILE" | head -1 | sed 's/.*: *"//' | sed 's/".*//')
WORKSPACE=$(grep "workspace_name:" "$CONFIG_FILE" | head -1 | sed 's/.*: *"//' | sed 's/".*//')

az account set --subscription "$SUBSCRIPTION_ID" 2>/dev/null || {
    echo "ERROR: Cannot set subscription"
    exit 1
}

echo "Subscription: $SUBSCRIPTION_ID"
echo "Resource Group: $RESOURCE_GROUP"
echo "Workspace: $WORKSPACE"
echo ""

TOTAL=$(python3 -c "import json; print(len(json.load(open('$RULES_FILE')).get('rules',[])))")
echo "Baseline rules to deploy: $TOTAL"
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "=== DRY RUN ==="
    python3 -c "
import json
with open('$RULES_FILE') as f:
    data = json.load(f)
for d in data.get('domains', []):
    print(f\"  [{d['weight'].upper()}] {d['domain']}: {d['rule_count']} rules\")
print(f\"\\nTotal: {data['total_rules']} rules across {data['domains_covered']} domains\")
"
    exit 0
fi

python3 -c "
import json, subprocess, sys, uuid
with open('$RULES_FILE') as f:
    data = json.load(f)
rules = data.get('rules', [])
success = 0
failed = 0
for r in rules:
    try:
        query = r.get('query', '')
        if not query:
            print(f\"  SKIP {r['rule_id']}: empty query\")
            failed += 1
            continue
        rule_id = str(uuid.uuid4())
        sev = str(r.get('severity', r.get('severity_label', 'MEDIUM'))).upper()
        severity = {'LOW':'Low','MEDIUM':'Medium','HIGH':'High','CRITICAL':'High'}.get(sev, 'Medium')
        body = json.dumps({'kind':'Scheduled','properties':{'displayName':r['rule_id'],'description':r.get('description',r.get('name',''))[:500],'query':query,'queryFrequency':r.get('queryFrequency','PT5M'),'queryPeriod':r.get('queryPeriod','PT10M'),'triggerOperator':r.get('triggerOperator','GreaterThan'),'triggerThreshold':int(r.get('triggerThreshold',3)),'severity':severity,'tactics':r.get('tactics',['Collection'])}})
        cmd = ['az','rest','--method','put','--url',f\"/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE/providers/Microsoft.SecurityInsights/alertRules/{rule_id}\",'--url-parameters','api-version=2024-03-01','--body',body]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f\"  OK {r['rule_id']}\")
            success += 1
        else:
            print(f\"  FAIL {r['rule_id']}: {result.stderr[:80]}\")
            failed += 1
    except Exception as e:
        print(f\"  FAIL {r['rule_id']}: {e}\")
        failed += 1
print(f\"\\nDeployed: {success} | Failed: {failed} | Total: {success+failed}\")
sys.exit(0 if failed == 0 else 1)
"
'''
    
    with open(pkg_dir / "deploy.sh", "w") as f:
        f.write(deploy)
    os.chmod(pkg_dir / "deploy.sh", 0o755)
    
    return len(rules), len(domains)

def write_readme(oracle_count, oracle_domains, azure_count, azure_domains):
    """Write the baseline README."""
    pkg_dir = BASE / "deployments" / "baseline"
    
    readme = f"""# Minimum Baseline SIEM Rules

## Overview

The minimum baseline is the essential set of SIEM detection rules that should be deployed **first** on any Oracle Cloud Infrastructure or Microsoft Azure environment. These rules cover the foundational security domains required by NIS2, DORA, PCI-DSS, GDPR, and NIST 800-53.

## What's Included

### Oracle OCI Baseline: {oracle_count} rules across {oracle_domains} domains

### Microsoft Azure Baseline: {azure_count} rules across {azure_domains} domains

## Domains Covered

| Domain | Weight | Description |
|--------|--------|-------------|
| Authentication & Initial Access | CRITICAL | Brute force, failed logins, external access attempts |
| Privilege Escalation | CRITICAL | Admin role changes, policy modifications, unauthorized elevation |
| Lateral Movement | HIGH | Internal SSH/RDP, process execution across hosts |
| Data Exfiltration | HIGH | Large data transfers, unusual outbound traffic |
| Persistence | HIGH | New user creation, API keys, scheduled tasks, backdoors |
| Ransomware Detection | CRITICAL | Mass file encryption, storage spikes, ransom indicators |
| Reconnaissance & Scanning | MEDIUM | Port scans, dropped connections, service enumeration |
| Database Security | HIGH | SQL injection, failed connections, unauthorized queries |
| Supply Chain Security | HIGH | Image tampering, unauthorized deployments, dependency attacks |
| Zero-Day & Anomalous Activity | CRITICAL | Unexpected ports, anomalous patterns, novel exploits |
| SQL Injection | HIGH | Injection patterns, union selects, OR 1=1 attempts |
| SSRF | HIGH | Internal IP access, metadata endpoint queries |
| Remote Code Execution | CRITICAL | Code execution exploits, CVE-based RCE attempts |
| Execution & Process Activity | HIGH | PowerShell abuse, suspicious process creation |

## Compliance Coverage

| Framework | Coverage |
|-----------|----------|
| EU NIS2 Directive | Art. 15(1) — Risk management measures |
| EU DORA | Art. 5-11 — ICT risk management, detection, incident response |
| PCI-DSS v4.0 | Req. 6, 7, 8, 10, 11, 12 |
| GDPR | Art. 32, 33 — Security of processing, breach notification |
| NIST 800-53 Rev 5 | AC, AU, CM, CP, IA, SA, SC, SI, SR families |

## Deployment

### Oracle OCI
```bash
cd deployments/baseline/oracle/
# Edit deployment-config.yaml with your compartment and region
./deploy.sh --dry-run     # Validate first
./deploy.sh               # Deploy for real
```

### Microsoft Azure
```bash
cd deployments/baseline/azure/
# Edit deployment-config.yaml with your subscription and workspace
./deploy.sh --dry-run     # Validate first
./deploy.sh               # Deploy for real
```

## Why Minimum Baseline?

The minimum baseline provides:
1. **Immediate coverage** — 14 critical security domains from day one
2. **Regulatory compliance** — satisfies core detection requirements for NIS2, DORA, PCI-DSS, GDPR
3. **Low noise** — curated to avoid alert fatigue while covering essential threats
4. **Fast deployment** — focused rule set that deploys in minutes, not hours

After baseline deployment, expand coverage with the full rule sets or regulation-specific packages (NIS2, DORA).

## Contents

```
deployments/baseline/
├── README.md                        # This file
├── oracle/
│   ├── baseline-rules.json          # All Oracle baseline rules
│   ├── compliance-mapping.json      # Framework-to-rule mapping
│   ├── deployment-config.yaml       # Configuration template
│   └── deploy.sh                    # Deployment script
└── azure/
    ├── baseline-rules.json          # All Azure baseline rules
    ├── compliance-mapping.json      # Framework-to-rule mapping
    ├── deployment-config.yaml       # Configuration template
    └── deploy.sh                    # Deployment script
```

Generated: {datetime.now(timezone.utc).isoformat()}
"""
    with open(pkg_dir / "README.md", "w") as f:
        f.write(readme)

def main():
    print("=== Building Oracle Baseline ===")
    o_count, o_domains = build_baseline_package("oracle")
    print(f"Oracle baseline: {o_count} rules across {o_domains} domains")
    
    print("\n=== Building Azure Baseline ===")
    a_count, a_domains = build_baseline_package("azure")
    print(f"Azure baseline: {a_count} rules across {a_domains} domains")
    
    print("\n=== Writing README ===")
    write_readme(o_count, o_domains, a_count, a_domains)
    
    print("\n=== Verification ===")
    for platform in ["oracle", "azure"]:
        pdir = BASE / "deployments" / "baseline" / platform
        files = list(pdir.glob("*"))
        with open(pdir / "baseline-rules.json") as f:
            data = json.load(f)
        print(f"{platform}: {data['total_rules']} rules, {data['domains_covered']} domains, {len(files)} files")
    
    print("\n=== DONE ===")

if __name__ == "__main__":
    main()