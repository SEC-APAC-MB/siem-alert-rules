#!/bin/bash
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
    print(f"  [{d['weight'].upper()}] {d['domain']}: {d['rule_count']} rules")
print(f"\nTotal: {data['total_rules']} rules across {data['domains_covered']} domains")
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
            print(f"  OK {r['rule_id']}")
            success += 1
        else:
            print(f"  FAIL {r['rule_id']}: {result.stderr[:80]}")
            failed += 1
    except Exception as e:
        print(f"  FAIL {r['rule_id']}: {e}")
        failed += 1
print(f"\nDeployed: {success} | Failed: {failed} | Total: {success+failed}")
sys.exit(0 if failed == 0 else 1)
"
