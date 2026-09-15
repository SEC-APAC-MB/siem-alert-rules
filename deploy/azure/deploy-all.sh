#!/bin/bash
# Deploy all Azure Sentinel ARM templates
# 
# Prerequisites:
#   - Azure CLI installed: az login
#   - Sentinel workspace enabled
#   - Resource group containing the Log Analytics workspace
#
# Usage:
#   ./deploy-all.sh <resource-group-name>
#
# To deploy specific priority only:
#   ./deploy-all.sh <resource-group-name> critical    # MITRE, lateral movement, AI security
#   ./deploy-all.sh <resource-group-name> high        # Database, API, compliance
#   ./deploy-all.sh <resource-group-name> medium      # Generated packs, WSTG
#   ./deploy-all.sh <resource-group-name> low         # GitHub advisories

set -euo pipefail

RG="${1:-}"
PRIORITY="${2:-all}"

if [ -z "$RG" ]; then
    echo "Usage: $0 <resource-group-name> [critical|high|medium|low|all]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARM_DIR="$SCRIPT_DIR/arm-templates"

# Rule ID prefixes by priority
CRITICAL_PREFIXES="AZ-MITRE AZ-LATERAL AZ-AI-SEC"
HIGH_PREFIXES="AZ-DB-SEC AZ-API-SEC AZ-COMPLIANCE AZ-WSTG-04-09"
MEDIUM_PREFIXES="AZ-GEN AZ-WSTG-01 AZ-WSTG-04-06 AZ-WSTG-07 AZ-WSTG-10 AZ-MOBILE"
LOW_PREFIXES="AZ-GITHUB-ADV"

deploy_file() {
    local file="$1"
    local basename
    basename=$(basename "$file" _arm.json)
    echo "  Deploying: $basename..."
    if az deployment group create --resource-group "$RG" --template-file "$file" --query "properties.outputs.ruleId.value" -o tsv 2>/dev/null; then
        echo "  ✅ $basename deployed"
    else
        echo "  ❌ $basename failed (may already exist or query error)"
    fi
}

should_deploy() {
    local file="$1"
    local basename
    basename=$(basename "$file" _arm.json)
    
    case "$PRIORITY" in
        critical)
            for prefix in $CRITICAL_PREFIXES; do [[ "$basename" == ${prefix}* ]] && return 0; done
            return 1 ;;
        high)
            for prefix in $HIGH_PREFIXES; do [[ "$basename" == ${prefix}* ]] && return 0; done
            return 1 ;;
        medium)
            for prefix in $MEDIUM_PREFIXES; do [[ "$basename" == ${prefix}* ]] && return 0; done
            return 1 ;;
        low)
            for prefix in $LOW_PREFIXES; do [[ "$basename" == ${prefix}* ]] && return 0; done
            return 1 ;;
        all)
            return 0 ;;
        *)
            echo "Unknown priority: $PRIORITY"
            echo "Use: critical, high, medium, low, or all"
            exit 1 ;;
    esac
}

echo "=========================================="
echo "Azure Sentinel Rule Deployment"
echo "=========================================="
echo "Resource Group: $RG"
echo "Priority: $PRIORITY"
echo "Source: $ARM_DIR"
echo "=========================================="
echo ""

count=0
failed=0

for file in "$ARM_DIR"/*_arm.json; do
    [ -f "$file" ] || continue
    if should_deploy "$file"; then
        deploy_file "$file"
        count=$((count + 1))
    fi
done

echo ""
echo "=========================================="
echo "Deployment complete: $count rules processed"
echo "=========================================="