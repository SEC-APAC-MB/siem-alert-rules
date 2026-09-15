#!/bin/bash
# Deploy all OCI Cloud Guard Detector Recipes
#
# Prerequisites:
#   - OCI CLI installed and configured: oci setup config
#   - Cloud Guard enabled in the compartment
#   - Compartment OCID where detector recipes will be created
#
# Usage:
#   ./deploy-all.sh <compartment-id>
#
# To deploy specific priority only:
#   ./deploy-all.sh <compartment-id> critical    # MITRE, lateral movement, AI security
#   ./deploy-all.sh <compartment-id> high        # Database, API, compliance
#   ./deploy-all.sh <compartment-id> medium      # Generated packs, WSTG
#   ./deploy-all.sh <compartment-id> low         # GitHub advisories

set -euo pipefail

COMPARTMENT_ID="${1:-}"
PRIORITY="${2:-all}"

if [ -z "$COMPARTMENT_ID" ]; then
    echo "Usage: $0 <compartment-id> [critical|high|medium|low|all]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RECIPE_DIR="$SCRIPT_DIR/detector-recipes"

# Rule ID prefixes by priority
CRITICAL_PREFIXES="OCI-MITRE OCI-LATERAL OCI-AI-SEC"
HIGH_PREFIXES="OCI-DB-SEC OCI-API-SEC OCI-COMPLIANCE OCI-WSTG-04-09"
MEDIUM_PREFIXES="OCI-GEN OCI-WSTG-01 OCI-WSTG-04-06 OCI-WSTG-07 OCI-WSTG-10 OCI-MOBILE"
LOW_PREFIXES="OCI-GITHUB-ADV"

deploy_file() {
    local file="$1"
    local basename
    basename=$(basename "$file" _detector_recipe.json)
    echo "  Deploying: $basename..."
    if oci cloud-guard detector-recipe create --from-json "file://$file" --compartment-id "$COMPARTMENT_ID" 2>/dev/null; then
        echo "  ✅ $basename deployed"
    else
        echo "  ❌ $basename failed (may already exist or validation error)"
    fi
}

should_deploy() {
    local file="$1"
    local basename
    basename=$(basename "$file" _detector_recipe.json)
    
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
echo "OCI Cloud Guard Detector Recipe Deployment"
echo "=========================================="
echo "Compartment: $COMPARTMENT_ID"
echo "Priority: $PRIORITY"
echo "Source: $RECIPE_DIR"
echo "=========================================="
echo ""

count=0
failed=0

for file in "$RECIPE_DIR"/*_detector_recipe.json; do
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