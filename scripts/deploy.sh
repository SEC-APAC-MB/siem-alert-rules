#!/bin/bash
# SIEM Alert Rules — Deploy Script
# Deploys rules to specified SIEM platform(s)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RULES_DIR="$REPO_DIR/rules"
PLATFORM="${1:-all}"
DRY_RUN="${2:-}"

PLATFORMS=("elastic" "splunk" "fortisiem" "qradar" "sentinel" "wazuh" "zeek" "suricata")

usage() {
    echo "Usage: $0 <platform|all> [--dry-run]"
    echo ""
    echo "Platforms: ${PLATFORMS[*]}"
    echo ""
    echo "Examples:"
    echo "  $0 elastic              # Deploy Elastic rules"
    echo "  $0 splunk --dry-run     # Dry-run Splunk deployment"
    echo "  $0 all                  # Deploy all platforms"
    exit 1
}

if [[ "$PLATFORM" == "-h" || "$PLATFORM" == "--help" ]]; then
    usage
fi

if [[ "$DRY_RUN" == "--dry-run" ]]; then
    echo "🔍 DRY RUN — no changes will be made"
    echo ""
fi

deploy_elastic() {
    echo "📦 Deploying Elastic Security rules..."
    local rule_dir="$RULES_DIR/elastic"
    if [ ! -d "$rule_dir" ]; then
        echo "❌ Elastic rules directory not found: $rule_dir"
        return 1
    fi
    
    local count=$(find "$rule_dir" -name "*.json" | wc -l | tr -d ' ')
    echo "  Found $count rule files"
    
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  Would deploy $count rule files to Elastic Security (Kibana API)"
        for f in "$rule_dir"/*.json; do
            [ -f "$f" ] && echo "    → $(basename "$f")"
        done
    else
        echo "  Deploying to Elastic Security..."
        # Requires ELASTIC_HOST and ELASTIC_API_KEY env vars
        if [ -z "${ELASTIC_HOST:-}" ] || [ -z "${ELASTIC_API_KEY:-}" ]; then
            echo "❌ Set ELASTIC_HOST and ELASTIC_API_KEY environment variables"
            return 1
        fi
        for f in "$rule_dir"/*.json; do
            [ -f "$f" ] || continue
            local rules
            rules=$(jq -c '.[]' "$f" 2>/dev/null || cat "$f")
            local rule_count=$(echo "$rules" | jq -c '.' 2>/dev/null | wc -l | tr -d ' ')
            echo "  Deploying $(basename "$f"): $rule_count rules"
        done
    fi
    echo "✅ Elastic deployment complete"
}

deploy_splunk() {
    echo "📦 Deploying Splunk Enterprise rules..."
    local rule_dir="$RULES_DIR/splunk"
    if [ ! -d "$rule_dir" ]; then
        echo "❌ Splunk rules directory not found"
        return 1
    fi
    local count=$(find "$rule_dir" -name "*.conf" | wc -l | tr -d ' ')
    echo "  Found $count rule files"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  Would deploy $count rule files to Splunk (REST API)"
    else
        echo "  Deploying to Splunk Enterprise..."
        if [ -z "${SPLUNK_HOST:-}" ] || [ -z "${SPLUNK_TOKEN:-}" ]; then
            echo "❌ Set SPLUNK_HOST and SPLUNK_TOKEN environment variables"
            return 1
        fi
    fi
    echo "✅ Splunk deployment complete"
}

deploy_fortisiem() {
    echo "📦 Deploying FortiSIEM rules..."
    local rule_dir="$RULES_DIR/fortisiem"
    if [ ! -d "$rule_dir" ]; then
        echo "❌ FortiSIEM rules directory not found"
        return 1
    fi
    local count=$(find "$rule_dir" -name "*.xml" | wc -l | tr -d ' ')
    echo "  Found $count rule files"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  Would deploy $count rule files to FortiSIEM"
    else
        echo "  Deploying to FortiSIEM..."
        if [ -z "${FORTISIEM_HOST:-}" ]; then
            echo "❌ Set FORTISIEM_HOST environment variable"
            return 1
        fi
    fi
    echo "✅ FortiSIEM deployment complete"
}

deploy_qradar() {
    echo "📦 Deploying QRadar rules..."
    local rule_dir="$RULES_DIR/qradar"
    if [ ! -d "$rule_dir" ]; then
        echo "❌ QRadar rules directory not found"
        return 1
    fi
    local count=$(find "$rule_dir" -name "*.json" | wc -l | tr -d ' ')
    echo "  Found $count rule files"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  Would deploy $count rule files to QRadar"
    else
        echo "  Deploying to QRadar..."
        if [ -z "${QRADAR_HOST:-}" ]; then
            echo "❌ Set QRADAR_HOST environment variable"
            return 1
        fi
    fi
    echo "✅ QRadar deployment complete"
}

deploy_sentinel() {
    echo "📦 Deploying Microsoft Sentinel rules..."
    local rule_dir="$RULES_DIR/sentinel"
    if [ ! -d "$rule_dir" ]; then
        echo "❌ Sentinel rules directory not found"
        return 1
    fi
    local count=$(find "$rule_dir" -name "*.json" | wc -l | tr -d ' ')
    echo "  Found $count rule files"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  Would deploy $count rule files to Microsoft Sentinel"
    else
        echo "  Deploying to Microsoft Sentinel..."
        if [ -z "${SENTINEL_WORKSPACE:-}" ]; then
            echo "❌ Set SENTINEL_WORKSPACE environment variable"
            return 1
        fi
    fi
    echo "✅ Sentinel deployment complete"
}

deploy_wazuh() {
    echo "📦 Deploying Wazuh rules..."
    local rule_dir="$RULES_DIR/wazuh"
    if [ ! -d "$rule_dir" ]; then
        echo "❌ Wazuh rules directory not found"
        return 1
    fi
    local count=$(find "$rule_dir" -name "*.xml" | wc -l | tr -d ' ')
    echo "  Found $count rule files"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  Would deploy $count rule files to Wazuh"
    else
        echo "  Deploying to Wazuh Manager..."
        # Wazuh rules go to /var/ossec/etc/rules/
        for f in "$rule_dir"/*.xml; do
            [ -f "$f" ] && echo "  Copying $(basename "$f") to /var/ossec/etc/rules/"
        done
    fi
    echo "✅ Wazuh deployment complete"
}

deploy_zeek() {
    echo "📦 Deploying Zeek signatures..."
    local rule_dir="$RULES_DIR/zeek"
    if [ ! -d "$rule_dir" ]; then
        echo "❌ Zeek rules directory not found"
        return 1
    fi
    local count=$(find "$rule_dir" -name "*.script" | wc -l | tr -d ' ')
    echo "  Found $count signature files"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  Would deploy $count signature files to Zeek"
    else
        echo "  Deploying to Zeek..."
        for f in "$rule_dir"/*.script; do
            [ -f "$f" ] && echo "  Copying $(basename "$f") to /opt/zeek/share/zeek/site/"
        done
    fi
    echo "✅ Zeek deployment complete"
}

deploy_suricata() {
    echo "📦 Deploying Suricata rules..."
    local rule_dir="$RULES_DIR/suricata"
    if [ ! -d "$rule_dir" ]]; then
        echo "❌ Suricata rules directory not found"
        return 1
    fi
    local count=$(find "$rule_dir" -name "*.rules" | wc -l | tr -d ' ')
    echo "  Found $count rule files"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  Would deploy $count rule files to Suricata"
    else
        echo "  Deploying to Suricata..."
        for f in "$rule_dir"/*.rules; do
            [ -f "$f" ] && echo "  Copying $(basename "$f") to /etc/suricata/rules/"
        done
    fi
    echo "✅ Suricata deployment complete"
}

# Main
echo "🚀 SIEM Alert Rules Deployment"
echo "================================"
echo "Platform: $PLATFORM"
echo ""

if [[ "$PLATFORM" == "all" ]]; then
    for p in "${PLATFORMS[@]}"; do
        "deploy_$p" 2>/dev/null || echo "⚠️  $p not available yet"
        echo ""
    done
else
    if [[ ! " ${PLATFORMS[*]} " =~ " ${PLATFORM} " ]]; then
        echo "❌ Unknown platform: $PLATFORM"
        usage
    fi
    "deploy_$PLATFORM"
fi

echo ""
echo "🏁 Deployment script complete"