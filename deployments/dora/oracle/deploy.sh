#!/usr/bin/env bash
#
# Deploy OCI (Oracle Cloud Infrastructure) SIEM alert rules
#
# Uses the OCI CLI to create Monitoring Alarms and Events Rules
# for every rule bundled in rules.json (a deployment package).
#
# Default package: THIS directory's rules.json (regulation-specific).
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
#   - OCI CLI (https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm)
#   - An authenticated OCI session (config + key, or instance principal)
#   - A pre-created ONS notification topic (email/pager endpoint)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="${RULES_FILE:-$SCRIPT_DIR/rules.json}"
CONFIG_FILE=""
DRY_RUN=0
COMPLIANCE_FILTER=""
REGION=""

usage() {
    sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
    exit 0
}

# ─── argument parsing ────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG_FILE="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --compliance) COMPLIANCE_FILTER="${2:-}"; shift 2 ;;
        --region) REGION="${2:-}"; shift 2 ;;
        --help|-h) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

# ─── override defaults from config file ──────────────────────
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: config file not found: $CONFIG_FILE" >&2
        exit 1
    fi
    # yq is optional; fall back to grepping simple `key: value` lines
    parse_cfg() {
        local key="$1"
        if command -v yq >/dev/null 2>&1; then
            yq -r ".$key // empty" "$CONFIG_FILE" 2>/dev/null || true
        else
            awk -F': *' -v k="$key" '$1==k {gsub(/"/,"",$2); print $2}' "$CONFIG_FILE" 2>/dev/null || true
        fi
    }
    CONFIG_COMPARTMENT="$(parse_cfg 'oci.compartment_id')"
    CONFIG_METRIC_COMPARTMENT="$(parse_cfg 'oci.metric_compartment_id')"
    CONFIG_ONS_TOPIC="$(parse_cfg 'oci.ons_topic_id')"
    CONFIG_REGION="$(parse_cfg 'oci.region')"
    CONFIG_SUBTREE="$(parse_cfg 'oci.metric_compartment_id_in_subtree')"
    OCI_COMPARTMENT_ID="${OCI_COMPARTMENT_ID:-$CONFIG_COMPARTMENT}"
    [[ -z "$REGION" ]] && REGION="$CONFIG_REGION"
fi

OCI_COMPARTMENT_ID="${OCI_COMPARTMENT_ID:-}"
METRIC_COMPARTMENT_ID="${METRIC_COMPARTMENT_ID:-${OCI_COMPARTMENT_ID}}"
ONS_TOPIC_ID="${ONS_TOPIC_ID:-${CONFIG_ONS_TOPIC:-}}"
SUBTREE="${SUBTREE:-${CONFIG_SUBTREE:-false}}"

# ─── prerequisites ───────────────────────────────────────────
echo "== OCI deployment prerequisites =="
if ! command -v oci >/dev/null 2>&1; then
    echo "ERROR: 'oci' CLI is not installed. See https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm" >&2
    exit 1
fi
OCI_VERSION="$(oci --version)"
echo "  oci CLI: $OCI_VERSION"

if [[ -z "$OCI_COMPARTMENT_ID" ]]; then
    echo "ERROR: OCI_COMPARTMENT_ID is empty. Set env var or provide 'compartment_id' in --config." >&2
    exit 1
fi
if [[ ! "$OCI_COMPARTMENT_ID" =~ ^ocid1\.compartment\. ]]; then
    echo "ERROR: OCI_COMPARTMENT_ID does not look like a compartment OCID: $OCI_COMPARTMENT_ID" >&2
    exit 1
fi
echo "  compartment: $OCI_COMPARTMENT_ID"

# auth + compartment reachability
if [[ -n "$REGION" ]]; then
    export OCI_REGION="$REGION"
fi
if ! oci iam compartment get --compartment-id "$OCI_COMPARTMENT_ID" >/dev/null 2>&1; then
    echo "ERROR: cannot authenticate / reach compartment $OCI_COMPARTMENT_ID. Check OCI CLI config (region, tenancy, user, key) and IAM policy." >&2
    exit 1
fi
echo "  authentication: OK"

if [[ -z "$ONS_TOPIC_ID" ]]; then
    echo "WARN: no ONS topic configured (oci.ons_topic_id). Alarms will be created WITHOUT notifications."
fi

# ─── load package rules ──────────────────────────────────────
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
    case "$PACKAGE_REGULATION" in
        "$COMPLIANCE_FILTER"|"ALL") echo "  compliance filter: all package rules match '$COMPLIANCE_FILTER'" ;;
        *)
            echo "  compliance filter '$COMPLIANCE_FILTER' requested but package is '$PACKAGE_REGULATION'. Deploying only rules tagged '$COMPLIANCE_FILTER'."
            ;;
    esac
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo ""
    echo "== DRY RUN — validating without deploying =="
fi

# ─── helpers ─────────────────────────────────────────────────
deploy_alarm() {
    local rule="$1"
    local id name severity query operator threshold dtype
    id="$(jq -r '.rule_id' <<< "$rule")"
    name="$(jq -r '.rule_id' <<< "$rule")"
    severity="$(jq -r '.severity // "LOW"' <<< "$rule")"
    query="$(jq -r '.query' <<< "$rule")"
    operator="$(jq -r '.condition.operator // "GT"' <<< "$rule")"
    threshold="$(jq -r '.condition.threshold // 1' <<< "$rule")"
    dtype="$(jq -r '.condition.eventType[0] // "com.oracle.cloud.monitoring"' <<< "$rule")"

    local args=(
        --display-name "$name"
        --compartment-id "$OCI_COMPARTMENT_ID"
        --metric-compartment-id "$METRIC_COMPARTMENT_ID"
        --metric-compartment-id-in-subtree "$SUBTREE"
        --namespace "SIEM/Security"
        --query-text "$query"
        --severity "$severity"
        --threshold "$threshold"
        --comparison-type "$operator"
        --resolution "PT5M"
        --pending-duration "PT5M"
        --body "SIEM alert triggered by ${id}"
    )
    if [[ -n "$ONS_TOPIC_ID" ]]; then
        args+=(--destinations "$ONS_TOPIC_ID")
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  [alarm]  $id  →  oci monitoring alarm create ${args[*]}"
        return 0
    fi
    if oci monitoring alarm create "${args[@]}" >/dev/null 2>&1; then
        echo "  OK       $id  (alarm)"
    else
        echo "  FAIL     $id  (alarm) — see above"
        return 1
    fi
}

deploy_event_rule() {
    local rule="$1"
    local id name evt condition actions
    id="$(jq -r '.rule_id' <<< "$rule")"
    name="$(jq -r '.rule_id' <<< "$rule")"
    evt="$(jq -c '[.condition.eventType[]]' <<< "$rule")"
    evt="${evt//[/}"
    evt="${evt//]/}"
    # JSON body for the events rule condition
    condition="$(jq -c '{eventType: .condition.eventType, compartmentId: .condition.compartmentId}' <<< "$rule")"
    if [[ -n "$ONS_TOPIC_ID" ]]; then
        actions="$(jq -nc --arg t "$ONS_TOPIC_ID" '{actions: [{actionType: "ONS", topicId: $t}]}')"
    else
        actions='{"actions":[]}'
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  [events] $id  →  oci events rule create --display-name $name --condition '$condition' --actions '$actions'"
        return 0
    fi
    if oci events rule create \
        --display-name "$name" \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --condition "$condition" \
        --actions "$actions" >/dev/null 2>&1; then
        echo "  OK       $id  (events rule)"
    else
        echo "  FAIL     $id  (events rule) — see above"
        return 1
    fi
}

# ─── main loop ───────────────────────────────────────────────
echo ""
echo "== Deploying rules =="
SUCCESS=0
FAILED=0
SKIPPED=0
while IFS= read -r rule; do
    [[ -z "$rule" ]] && continue

    # compliance filter support
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

    evt="$(jq -r '.condition.eventType[0] // ""' <<< "$rule")"
    if [[ "$evt" == *"audit"* ]]; then
        deploy_alarm "$rule" || FAILED=$((FAILED + 1))
        if [[ "$DRY_RUN" -ne 1 ]]; then
            deploy_event_rule "$rule" || FAILED=$((FAILED + 1))
        fi
        SUCCESS=$((SUCCESS + 1))
    else
        deploy_alarm "$rule" || FAILED=$((FAILED + 1))
        SUCCESS=$((SUCCESS + 1))
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
echo "✅ OCI deployment complete"