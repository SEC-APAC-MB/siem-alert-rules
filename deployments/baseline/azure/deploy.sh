#!/bin/bash
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
    print(f"  [{d['weight'].upper()}] {d['domain']}: {d['rule_count']} rules")
print(f"\nTotal: {data['total_rules']} rules across {data['domains_covered']} domains")
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
            print(f"  SKIP {r['rule_id']}: empty query")
            failed += 1
            continue
        rule_id = str(uuid.uuid4())
        sev = str(r.get('severity', r.get('severity_label', 'MEDIUM'))).upper()
        severity = {'LOW':'Low','MEDIUM':'Medium','HIGH':'High','CRITICAL':'High'}.get(sev, 'Medium')
        body = json.dumps({'kind':'Scheduled','properties':{'displayName':r['rule_id'],'description':r.get('description',r.get('name',''))[:500],'query':query,'queryFrequency':r.get('queryFrequency','PT5M'),'queryPeriod':r.get('queryPeriod','PT10M'),'triggerOperator':r.get('triggerOperator','GreaterThan'),'triggerThreshold':int(r.get('triggerThreshold',3)),'severity':severity,'tactics':r.get('tactics',['Collection'])}})
        cmd = ['az','rest','--method','put','--url',f"/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE/providers/Microsoft.SecurityInsights/alertRules/{rule_id}",'--url-parameters','api-version=2024-03-01','--body',body]
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
