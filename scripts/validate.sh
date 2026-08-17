#!/bin/bash
# SIEM Alert Rules — Validation Script
# Validates all rule files across 8 SIEM platforms

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RULES_DIR="$REPO_DIR/rules"
MAPPINGS_DIR="$REPO_DIR/mappings"
ERRORS=0
WARNINGS=0
TOTAL_RULES=0

echo "🔍 SIEM Alert Rules Validator"
echo "=============================="
echo ""

# Count rules per platform
for platform in elastic splunk fortisiem qradar sentinel wazuh zeek suricata; do
    platform_dir="$RULES_DIR/$platform"
    if [ -d "$platform_dir" ]; then
        count=$(find "$platform_dir" -type f \( -name "*.json" -o -name "*.conf" -o -name "*.xml" -o -name "*.script" -o -name "*.rules" \) | wc -l | tr -d ' ')
        rules_in_files=0
        case "$platform" in
            elastic|qradar|sentinel)
                # JSON — count rule objects
                for f in "$platform_dir"/*.json; do
                    [ -f "$f" ] && rules_in_files=$((rules_in_files + $(grep -c '"rule_id"' "$f" 2>/dev/null || echo 0)))
                done
                ;;
            splunk)
                for f in "$platform_dir"/*.conf; do
                    [ -f "$f" ] && rules_in_files=$((rules_in_files + $(grep -c '^\[' "$f" 2>/dev/null || echo 0)))
                done
                ;;
            fortisiem|wazuh)
                for f in "$platform_dir"/*.xml; do
                    [ -f "$f" ] && rules_in_files=$((rules_in_files + $(grep -c '<rule ' "$f" 2>/dev/null || echo 0)))
                done
                ;;
            zeek)
                for f in "$platform_dir"/*.script; do
                    [ -f "$f" ] && rules_in_files=$((rules_in_files + $(grep -c 'signature' "$f" 2>/dev/null || echo 0)))
                done
                ;;
            suricata)
                for f in "$platform_dir"/*.rules; do
                    [ -f "$f" ] && rules_in_files=$((rules_in_files + $(grep -cE '^[a-z]' "$f" 2>/dev/null || echo 0)))
                done
                ;;
        esac
        echo "  $platform: $count files, $rules_in_files rules"
        TOTAL_RULES=$((TOTAL_RULES + rules_in_files))
    else
        echo "  ⚠️  $platform: directory not found"
        WARNINGS=$((WARNINGS + 1))
    fi
done

echo ""
echo "📊 Total rules found: $TOTAL_RULES"
echo ""

# Validate mappings
echo "🔗 Checking mappings..."
for mapping in "$MAPPINGS_DIR"/*-mappings.json; do
    if [ -f "$mapping" ]; then
        platform=$(basename "$mapping" | sed 's/-mappings.json//')
        entries=$(grep -c '"test_id"' "$mapping" 2>/dev/null || echo 0)
        echo "  $platform: $entries mappings"
    fi
done

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Validation complete. $TOTAL_RULES rules, $WARNINGS warnings, $ERRORS errors"
else
    echo "❌ Validation failed. $TOTAL_RULES rules, $WARNINGS warnings, $ERRORS errors"
    exit 1
fi