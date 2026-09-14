#!/usr/bin/env bash
#
# Deploy Microsoft Sentinel SIEM alert rules
#
# Uses the Azure CLI (az) to create Sentinel Scheduled analytics rules
# (Microsoft Sentinel) for every rule bundled in rules.json.
#
# Usage:
#   ./deploy.sh                          # deploy all rules in rules.json
#   ./deploy.sh --config ../deployment-config.yaml
#   ./deploy.sh --dry-run                # validate without deploying
#   ./deploy.sh --compliance NIS2        # only deploy rules referenced by NIS2
#   ./deploy.sh --compliance DORA
#   ./deploy.sh --help
#
# Requires:
#   - Azure CLI (https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
#   - az sentinel extension:   az extension add --name sentinel
#   - An authenticated session (az login / service principal)
#   - A Log Analytics workspace with Microsoft Sentinel enabled
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="${RULES_FILE:-$SCRIPT_DIR/rules.json}"
CONFIG_FILE=""
DRY_RUN=0
COMPLIANCE_FILTER=""

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG_FILE="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --compliance) COMPLIANCE_FILTER="${2:-}"; shift 2 ;;
        --help|-h) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

parse_cfg() {
    local key="$1"
    if command -v yq >/dev/null 2>&1; then
        yq -r ".$key // empty" "$CONFIG_FILE" 2>/dev/null || true
    else
        awk -F': *' -v k="$key" '$1==k {gsub(/"/,"",$2); print $2}' "$CONFIG_FILE" 2>/dev/null || true
    fi
}

if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: config file not found: $CONFIG_FILE" >&2
        exit 1
    fi
    AZ_SUBSCRIPTION_ID="${AZ_SUBSCRIPTION_ID:-$(parse_cfg 'azure.subscription_id')}"
    AZ_RESOURCE_GROUP="${AZ_RESOURCE_GROUP:-$(parse_cfg 'azure.resource_group')}"
    AZ_WORKSPACE_NAME="${AZ_WORKSPACE_NAME:-$(parse_cfg 'azure.workspace_name')}"
fi

AZ_SUBSCRIPTION_ID="${AZ_SUBSCRIPTION_ID:-}"
AZ_RESOURCE_GROUP="${AZ_RESOURCE_GROUP:-}"
AZ_WORKSPACE_NAME="${AZ_WORKSPACE_NAME:-}"

echo "== Azure deployment prerequisites =="
if ! command -v az >/dev/null 2>&1; then
    echo "ERROR: 'az' CLI is not installed. See https://docs.microsoft.com/en-us/cli/azure/install-azure-cli" >&2
    exit 1
fi
echo "  az CLI: $(az version --query '[0].azure-cli' -o tsv 2>/dev/null)"
if ! az extension list --query "[?contains(name, 'sentinel')]" | grep -q sentinel; then
    echo "  NOTE: 'sentinel' extension not found — run 'az extension add --name sentinel'"
fi

if [[ -z "$AZ_SUBSCRIPTION_ID" ]]; then
    echo "ERROR: AZ_SUBSCRIPTION_ID is empty. Set env var or provide 'subscription_id' in --config." >&2
    exit 1
fi
if [[ -z "$AZ_RESOURCE_GROUP" ]]; then
    echo "ERROR: AZ_RESOURCE_GROUP is empty. Set env var or provide 'resource_group' in --config." >&2
    exit 1
fi
if [[ -z "$AZ_WORKSPACE_NAME" ]]; then
    echo "ERROR: AZ_WORKSPACE_NAME is empty. Set env var or provide 'workspace_name' in --config." >&2
    exit 1
fi
echo "  subscription: $AZ_SUBSCRIPTION_ID"
echo "  resource group: $AZ_RESOURCE_GROUP"
echo "  workspace: $AZ_WORKSPACE_NAME"

if ! az account show --subscription "$AZ_SUBSCRIPTION_ID" >/dev/null 2>&1; then
    echo "ERROR: cannot authenticate / access subscription $AZ_SUBSCRIPTION_ID. Run 'az login' first." >&2
    exit 1
fi
az account set --subscription "$AZ_SUBSCRIPTION_ID" >/dev/null
echo "  authentication: OK"

# ─── load package ────────────────────────────────────────────
if [[ ! -f "$RULES_FILE" ]]; then
    echo "ERROR: rules file not found: $RULES_FILE" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: 'jq' is required. Install with 'brew install jq' or 'apt install jq'." >&2
    exit 1
fi
PACKAGE_REGULATION="$(jq -r '.regulation // "UNKNOWN"' "$RULES_FILE")"
TOTAL="$(jq '[.rules[]] | length' "$RULES_FILE")"
echo ""
echo "== Package: $RULES_FILE =="
echo "  regulation: $PACKAGE_REGULATION"
echo "  rules: $TOTAL"

if [[ -n "$COMPLIANCE_FILTER" ]]; then
    echo "  compliance filter: '$COMPLIANCE_FILTER'"
fi
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo ""
    echo "== DRY RUN — validating without deploying =="
fi

normalize_freq() {
    local v="$1"
    case "$v" in
        PT*) echo "$v" ;;
        *) echo "${v/m/M}" | sed 's/^\([0-9]*\)h$/PT\1H/; s/^\([0-9]*\)$/PT\1M/; s/^\([0-9]*\)m$/PT\1M/; s/^\([0-9]*\)d$/P\1D/' ;;
    esac
}

sev_to_sentinel() {
    case "$1" in
        0) echo "High" ;;
        1) echo "Medium" ;;
        2) echo "Low" ;;
        3) echo "Informational" ;;
        *) echo "Low" ;;
    esac
}

echo ""
echo "== Deploying rules =="
SUCCESS=0
FAILED=0
SKIPPED=0

while IFS= read -r rule; do
    [[ -z "$rule" ]] && continue

    if [[ -n "$COMPLIANCE_FILTER" && "$COMPLIANCE_FILTER" != "ALL" ]]; then
        refs="$(jq -c '.regulation_refs // []' <<< "$rule")"
        case "$refs" in
            *"$COMPLIANCE_FILTER"*) ;;
            *)
                echo "  SKIP     $(jq -r '.rule_id' <<< "$rule")  (not tagged $COMPLIANCE_FILTER)"
                SKIPPED=$((SKIPPED + 1))
                continue
                ;;
        esac
    fi

    id="$(jq -r '.rule_id' <<< "$rule")"
    name="$(jq -r '.rule_id' <<< "$rule")"
    display="$(jq -r '.name' <<< "$rule")"
    desc="$(jq -r '.description // ""' <<< "$rule")"
    sev="$(sev_to_sentinel "$(jq -r '.severity // 2' <<< "$rule")")"
    query="$(jq -r '.query' <<< "$rule")"
    freq="$(normalize_freq "$(jq -r '.queryFrequency // "5m"' <<< "$rule")")"
    period="$(normalize_freq "$(jq -r '.queryPeriod // "10m"' <<< "$rule")")"
    op="$(jq -r '.triggerOperator // "GreaterThan"' <<< "$rule")"
    thr="$(jq -r '.triggerThreshold // 1' <<< "$rule")"
    tactics="$(jq -r '[.tactics[]?] | join(",")' <<< "$rule")"

    local_args=(
        --resource-group "$AZ_RESOURCE_GROUP"
        --workspace-name "$AZ_WORKSPACE_NAME"
        --name "$id"
        --kind "Scheduled"
        --display-name "$display"
        --description "$desc"
        --severity "$sev"
        --query "$query"
        --query-frequency "$freq"
        --query-period "$period"
        --trigger-operator "$op"
        --trigger-threshold "$thr"
        --enabled true
    )
    [[ -n "$tactics" ]] && local_args+=(--tactics "$tactics")

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  OK       $id  (would run: az sentinel alert-rule create ...)"
        SUCCESS=$((SUCCESS + 1))
        continue
    fi
    if az sentinel alert-rule create "${local_args[@]}" >/dev/null 2>&1; then
        echo "  OK       $id  ($display)"
        SUCCESS=$((SUCCESS + 1))
    else
        echo "  FAIL     $id  ($display) — see above"
        FAILED=$((FAILED + 1))
    fi
done < <(jq -c '.rules[]' "$RULES_FILE")

echo ""
echo "== Summary =="
echo "  success: $SUCCESS"
echo "  failed:  $FAILED"
echo "  skipped: $SKIPPED"

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "  DRY RUN — no resources were created or modified."
fi

if [[ "$FAILED" -gt 0 ]]; then
    echo "ERROR: $FAILED rule(s) failed to deploy" >&2
    exit 1
fi
echo "✅ Azure deployment complete"