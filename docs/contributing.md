# Contributing Guide

Thank you for contributing to the SIEM Alert Rules repository. This guide covers how to add new rules, follow naming conventions, meet required fields, submit pull requests, and maintain cross-reference integrity across all 11 platforms and 8 regulatory frameworks.

---

## How to Contribute New Rules

### Quick Start

1. **Fork** the repository
2. **Create a branch** for your contribution: `git checkout -b feature/my-new-rules`
3. **Add rules** for all 11 platforms (see Rule Templates below)
4. **Add cross-mappings** to all relevant mapping files
5. **Validate** with `./scripts/validate.sh`
6. **Test** with `./scripts/deploy.sh <platform> --dry-run`
7. **Commit** and submit a pull request

### When to Contribute

- **New detection capability**: A threat vector not yet covered (e.g., a new AI attack pattern, a new MITRE technique)
- **Platform coverage**: An existing detection concept missing from one or more platforms
- **Regulatory mapping**: A compliance framework control not yet mapped
- **Rule improvement**: Better detection logic, reduced false positives, or improved accuracy
- **Bug fix**: Incorrect query syntax, wrong severity, missing cross-references

### Contribution Checklist

Before submitting a pull request, verify:

- [ ] Rules added for **all 11 platforms** (or an explanation for exceptions)
- [ ] Rule IDs follow the naming convention for each platform
- [ ] All required fields are present in every rule
- [ ] Cross-references (MITRE, compliance, test IDs) are accurate
- [ ] Mappings updated in all relevant files
- [ ] `validate.sh` passes with zero errors
- [ ] `deploy.sh --dry-run` succeeds for all platforms
- [ ] No duplicate rule IDs
- [ ] Severity and risk score are consistent across platforms
- [ ] Pull request description explains the detection rationale

---

## Rule Templates

### Elastic Security (JSON)

```json
{
  "rule_id": "ES-{CATEGORY}-{NUMBER}",
  "name": "{Category} — {Descriptive Name}",
  "description": "Detects {what} via {method} indicating {threat}",
  "severity": "critical|high|medium|low|informational",
  "type": "query",
  "query": "event.category:(\"{category}\") AND (\"{keyword1}\" OR \"{keyword2}\")",
  "index": ["logs-*"],
  "references": ["{TEST-ID}"],
  "mitre": ["{TECHNIQUE-ID}"],
  "compliance": ["{REGULATORY-REF}"],
  "tags": ["{tag1}", "{tag2}", "{tag3}"],
  "risk_score": 90,
  "interval": "5m"
}
```

**Required fields**: `rule_id`, `name`, `description`, `severity`, `type`, `query`, `index`, `references`, `mitre`, `compliance`, `tags`, `risk_score`

**Optional fields**: `interval` (default: `5m`), `threshold` (for threshold rules), `from` (EQL sequence rules)

**Container format**:
```json
{
  "description": "Elastic Security SIEM alert rules — {category}",
  "version": "1.0.0",
  "elastic_version": "8.x",
  "total_rules": N,
  "rules": [ /* rule objects */ ]
}
```

### Splunk (INI/conf format)

```ini
[SPL-{CATEGORY}-{NUMBER}]
name = {Category} — {Descriptive Name}
description = Detects {what} via {method} indicating {threat}
severity = critical|high|medium|low|informational
search = index=* ("{keyword1}" OR "{keyword2}") | stats count, values(src_ip) as src_ips, values(dest_ip) as dest_ips by rule_id, rule_name | where count > 5
sourcetype = {sourcetype1},{sourcetype2}
action = email|notable
references = {TEST-ID}
mitre = {TECHNIQUE-ID}
compliance = {REGULATORY-REF1},{REGULATORY-REF2}
risk_score = 90
```

**Required fields**: stanza header (rule ID), `name`, `description`, `severity`, `search`, `sourcetype`, `action`, `references`, `mitre`, `compliance`, `risk_score`

### FortiSIEM (XML)

```xml
<Rule name="FSIEM-{CATEGORY}-{NUMBER}" id="FSIEM-{CATEGORY}-{NUMBER}">
  <Description>Detects {what} via {method} indicating {threat}</Description>
  <Severity>Critical|High|Medium|Low|Info</Severity>
  <Pattern>"{keyword1}" OR "{keyword2}"</Pattern>
  <EventType>{EVENT_TYPE}</EventType>
  <MITRE>{TECHNIQUE-ID}</MITRE>
  <Compliance>{REGULATORY-REF1},{REGULATORY-REF2}</Compliance>
</Rule>
```

**Required fields**: `name`/`id` attribute, `Description`, `Severity`, `Pattern`, `EventType`, `MITRE`, `Compliance`

**Container**: Wrapped in `<Rules>` root element with XML declaration and comment header.

### QRadar (JSON with AQL)

```json
{
  "rule_id": "QR-{CATEGORY}-{NUMBER}",
  "name": "{Category} — {Descriptive Name}",
  "description": "Detects {what} via {method} indicating {threat}",
  "severity": 9,
  "aql_query": "SELECT sourceip, destinationip, URL, payload FROM events WHERE (payload ILIKE '%keyword1%' OR payload ILIKE '%keyword2%') GROUP BY sourceip, destinationip, URL LAST 15 MINUTES",
  "log_source": "APPLICATION_LOG",
  "references": ["{TEST-ID}"],
  "mitre": {
    "tactic": "{MITRE_TACTIC}",
    "technique": "{TECHNIQUE-ID}"
  },
  "compliance": ["{REGULATORY-REF}"],
  "credibility": 7,
  "relevance": 9
}
```

**Required fields**: `rule_id`, `name`, `description`, `severity` (1-10 numeric), `aql_query`, `log_source`, `references`, `mitre`, `compliance`

**Optional fields**: `credibility` (1-10, default 7), `relevance` (1-10, default based on severity)

### Microsoft Sentinel (JSON with KQL)

```json
{
  "rule_id": "MS-{CATEGORY}-{NUMBER}",
  "name": "{Category} — {Descriptive Name}",
  "description": "Detects {what} via {method} indicating {threat}",
  "severity": "High|Medium|Low|Informational",
  "query": "let threshold = 5;\n{table_name}\n| where {field} has_any(\"keyword1\", \"keyword2\")\n| summarize count() by SourceIP, bin(TimeGenerated, 5m)\n| where count_ > threshold",
  "queryFrequency": "PT5M",
  "queryPeriod": "PT5M",
  "triggerOperator": "GreaterThan",
  "triggerThreshold": 5,
  "tactics": ["{MITRE_TACTIC}"],
  "techniques": ["{TECHNIQUE-ID}"],
  "references": ["{TEST-ID}"],
  "compliance": ["{REGULATORY-REF}"],
  "tags": ["{tag1}", "{tag2}"],
  "risk_score": 90
}
```

**Required fields**: `rule_id`, `name`, `description`, `severity`, `query`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, `tactics`, `techniques`, `references`, `compliance`, `tags`, `risk_score`

### Wazuh (XML)

```xml
<rule id="WZ-{COMPACT_ID}" level="{9|7|5|3|1}" group="{tag1},{tag2},{tag3}">
  <description>{Category} — {Descriptive Name} — Detects {what}</description>
  <decoded_as>{decoder}</decoded_as>
  <field name="test_id">{TEST-ID}</field>
  <mitre><id>{TECHNIQUE-ID}</id></mitre>
  <match>{keyword1}|{keyword2}</match>
</rule>
```

**Required fields**: `id` attribute (WZ prefix + compact alphanumeric), `level` attribute, `group` attribute, `description`, `decoded_as`, `field name="test_id"`, `mitre`, `match`

**Wazuh-specific notes**:
- Rule IDs use compact format without hyphens in sub-IDs: `WZ-AIPI001`, `WZ-WSTG01001`
- `level` mapping: 9-10 = critical, 7-8 = high, 5-6 = medium, 3-4 = low, 0-2 = informational
- Rules must be wrapped in a `<group name="wazuh,{category},security">` container

### Zeek (Signatures)

```zeek
# =============================================================================
# Zeek Signatures — {category}
# Total rules: N
# =============================================================================

signature ZK-{COMPACT_ID} {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /{keyword1}|{keyword2}/
	event "Detect_{Descriptive_Name}"
}
```

**Required fields**: signature name, `ip-proto`, `src-ip`, `dst-port`, `payload`, `event`

**Zeek-specific notes**:
- Uses compact IDs: `ZK-AIPI001`, `ZK-API001`, `ZK-LM001`
- Payload patterns use regex syntax `/pattern/`
- File extension is `.zeek`
- Each file has a header comment with category name and total rule count

### Suricata (Rules)

```
SUR-{CATEGORY}-{NUMBER} http any any -> $HOME_NET any (msg:"SIEM {Category} — {Descriptive Name}"; content:"{keyword1}"; content:"{keyword2}"; classtype:attempted-admin; sid:{UNIQUE_SID}; rev:1; severity:{1|2|3|4}; metadata:mitre {TECHNIQUE-ID};)
```

**Required fields**: rule ID, `msg`, `content` (at least one), `classtype`, `sid`, `rev`, `severity`, `metadata`

**Suricata-specific notes**:
- `sid` starts at 3000000 for custom rules
- `severity`: 1 = critical, 2 = high, 3 = medium, 4 = low
- `classtype` values: `attempted-admin`, `attempted-recon`, `policy-violation`, etc.
- Each file has a header comment with category name and total rule count

### Oracle Cloud Infrastructure (JSON)

```json
{
  "rule_id": "OCI-{CATEGORY}-{NUMBER}",
  "name": "{Category} — {Descriptive Name}",
  "description": "Detects {what} via {method} indicating {threat}",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "condition": {
    "eventType": ["com.oracle.cloud.monitoring"],
    "compartmentId": "$COMPARTMENT_ID",
    "metric": "{metric_name}",
    "operator": "GT",
    "threshold": 5
  },
  "actions": [
    {"actionType": "ONS", "description": "Send alert notification"}
  ],
  "references": ["{REGULATORY-REF}"],
  "mitre": ["{TECHNIQUE-ID}"],
  "tags": ["{tag1}", "{tag2}"]
}
```

**Required fields**: `rule_id`, `name`, `description`, `severity`, `condition`, `actions`, `references`, `mitre`, `tags`

**OCI-specific notes**: `$COMPARTMENT_ID` is a placeholder replaced during deployment.

### Azure (JSON with KQL)

```json
{
  "rule_id": "AZ-{CATEGORY}-{NUMBER}",
  "name": "{Category} — {Descriptive Name}",
  "description": "Detects {what} via {method} indicating {threat}",
  "severity": 0,
  "query": "AzureDiagnostics | where Category contains '{keyword}' | summarize count() by bin(TimeGenerated, 5m), resource_group | where count_ > 5",
  "queryFrequency": "PT5M",
  "queryPeriod": "PT5M",
  "triggerOperator": "GreaterThan",
  "triggerThreshold": 5,
  "tactics": ["{TECHNIQUE-ID}"],
  "compliance": ["{REGULATORY-REF}"],
  "tags": ["{tag1}", "{tag2}"],
  "risk_score": 90
}
```

**Required fields**: `rule_id`, `name`, `description`, `severity` (0=Critical, 1=High, 2=Medium, 3=Low, 4=Informational), `query`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, `tactics`, `compliance`, `tags`, `risk_score`

### AWS (JSON with CloudWatch/EventBridge/GuardDuty)

```json
{
  "rule_id": "AWS-{CATEGORY}-{NUMBER}",
  "name": "{Category} — {Descriptive Name}",
  "description": "Detects {what} via {method} indicating {threat}",
  "severity": "critical|high|medium|low|informational",
  "cloudwatch_metric": {
    "namespace": "SIEM/Security",
    "metricName": "{metric_name}",
    "dimensions": {"RuleId": "AWS-{CATEGORY}-{NUMBER}"},
    "statistic": "Sum",
    "period": 300,
    "evaluationPeriods": 1,
    "threshold": 5,
    "comparisonOperator": "GreaterThanThreshold"
  },
  "eventbridge_pattern": {
    "source": ["aws.security", "aws.guardduty", "aws.cloudtrail"],
    "detail-type": ["AWS API Call via CloudTrail", "GuardDuty Finding"],
    "detail": {"eventSource": [], "eventName": []}
  },
  "guardduty_finding": {
    "severity": 9,
    "type": "{FINDING_TYPE}"
  },
  "references": ["{TEST-ID}", "{REGULATORY-REF}"],
  "mitre": ["{TECHNIQUE-ID}"],
  "tags": ["{tag1}", "{tag2}"],
  "risk_score": 90
}
```

**Required fields**: `rule_id`, `name`, `description`, `severity`, `cloudwatch_metric`, `eventbridge_pattern`, `references`, `mitre`, `tags`, `risk_score`

**Optional fields**: `guardduty_finding` (for rules that map to GuardDuty)

---

## Naming Conventions

### Rule IDs

Rule IDs follow a strict format: `{PLATFORM_PREFIX}-{CATEGORY}-{SUBCATEGORY}-{NUMBER}`

**Platform prefixes** (always uppercase):

| Platform | Prefix | Example |
|----------|--------|---------|
| Elastic Security | `ES-` | `ES-AI-PI-001` |
| Splunk | `SPL-` | `SPL-AI-PI-001` |
| FortiSIEM | `FSIEM-` | `FSIEM-AI-PI-001` |
| QRadar | `QR-` | `QR-AI-PI-001` |
| Sentinel | `MS-` | `MS-AI-PI-001` |
| Wazuh | `WZ-` | `WZ-AIPI001` (compact) |
| Zeek | `ZK-` | `ZK-AIPI001` (compact) |
| Suricata | `SUR-` | `SUR-AI-PI-001` |
| OCI | `OCI-` | `OCI-AI-PI-001` |
| Azure | `AZ-` | `AZ-AI-PI-001` |
| AWS | `AWS-` | `AWS-AI-PI-001` |

**Category prefixes**:

| Category | Prefix | Example |
|----------|--------|---------|
| WSTG catalogs 01-03 | `WSTG01`–`WSTG03` | `ES-WSTG01-001` |
| WSTG catalogs 04-06 | `WSTG04`–`WSTG06` | `SPL-WSTG04-001` |
| WSTG catalogs 07-09 | `WSTG07`–`WSTG09` | `MS-WSTG07-001` |
| WSTG catalog 10 | `WSTG10` | `QR-WSTG10-001` |
| AI/LLM Security | `AI-` | `ES-AI-PI-001` |
| API Security | `API-` | `ES-API-001` |
| Mobile Security | `MOB-` | `ES-MOB-001` |
| Database Security | `DB-{DB_TYPE}-` | `ES-DB-PG-001` |
| MITRE ATT&CK | `MITRE-` | `ES-MITRE-T1190` |
| Lateral Movement | `LM-` | `ES-LM-001` |

**Subcategory prefixes** (AI security):

| Subcategory | Prefix |
|------------|--------|
| Prompt Injection | `PI` |
| Data Exfiltration | `DEX` |
| Model Integrity | `MDL` |
| RAG Pipeline | `RAG` |
| Hallucination | `HAL` |
| Bias Detection | `BIA` |
| Governance | `GOV` |
| Red Team | `RED` |
| Safety | `SAF` |
| Vector DB | `VEC` |

### Rule Names

Rule names follow the format: `{Category} — {Descriptive Name}`

Examples:
- `AI — Direct Prompt Injection`
- `WSTG-04 — Credentials Transmitted Over Unencrypted Channel`
- `Database — PostgreSQL Privilege Escalation via SET ROLE`
- `MITRE — Exploit Public-Facing Application`
- `Lateral Movement — Pass-the-Hash Detection`

### File Names

Files are named by category, using the platform's native extension:

| Category | Filename Pattern |
|----------|-----------------|
| AI Security | `ai-security.{json\|conf\|xml\|zeek\|rules}` |
| API Security | `api-security.{json\|conf\|xml\|zeek\|rules}` |
| Mobile Security | `mobile-security.{json\|conf\|xml\|zeek\|rules}` |
| Database Security | `database-security.{json\|conf\|xml\|zeek\|rules}` |
| MITRE ATT&CK | `mitre-attack.{json\|conf\|xml\|zeek\|rules}` |
| Lateral Movement | `lateral-movement.{json\|conf\|xml\|zeek\|rules}` |
| WSTG 01-03 | `wstg-01-03.{json\|conf\|xml\|zeek\|rules}` |
| WSTG 04-06 | `wstg-04-06.{json\|conf\|xml\|zeek\|rules}` |
| WSTG 07-09 | `wstg-07-09.{json\|conf\|xml\|zeek\|rules}` |
| WSTG 10 | `wstg-10-business-logic.{json\|conf\|xml\|zeek\|rules}` |

---

## Severity and Risk Score Guidelines

### Severity Assignment

| Severity | When to Use | Risk Score | Examples |
|----------|------------|------------|---------|
| Critical | Immediate threat, active exploitation, data exfiltration, RCE | 81-100 | Prompt injection, SQL injection, credential stuffing, pass-the-hash |
| High | Significant threat, auth bypass, privilege escalation, data exposure | 61-80 | IDOR, SSRF, weak TLS, missing MFA, training data extraction |
| Medium | Moderate threat, info disclosure, misconfig, weak crypto | 31-60 | Directory listing, verbose errors, missing headers, cache issues |
| Low | Low threat, reconnaissance, fingerprinting, metadata | 11-30 | Server version disclosure, HTTP method enumeration |
| Informational | No direct threat, visibility, context | 1-10 | Architecture fingerprinting, DNS zone transfer detection |

### Consistency Requirements

- The same detection concept must have the **same severity** across all 11 platforms
- Severity naming varies by platform — use the correct label:

| Standard | Elastic | Splunk | FortiSIEM | QRadar | Sentinel | Wazuh | Suricata | OCI | Azure |
|----------|---------|--------|-----------|--------|----------|-------|----------|-----|-------|
| Critical | critical | critical | Critical | 9-10 | High | 9-10 | 1 | CRITICAL | 0 |
| High | high | high | High | 7-8 | Medium | 7-8 | 2 | HIGH | 1 |
| Medium | medium | medium | Medium | 5-6 | Low | 5-6 | 3 | MEDIUM | 2 |
| Low | low | low | Low | 3-4 | Informational | 3-4 | 4 | LOW | 3 |
| Informational | informational | informational | Info | 1-2 | Informational | 0-2 | — | INFO | 4 |

### Risk Score Assignment

- Risk scores must be consistent for the same rule across all platforms
- Score ranges: Critical 81-100, High 61-80, Medium 31-60, Low 11-30, Informational 1-10
- Use round numbers: 90, 75, 50, 25, 5
- Within a category, differentiate scores to enable prioritized alerting

---

## Required Fields Checklist

Every rule must include these fields regardless of platform:

| Field | Required | Description |
|-------|----------|-------------|
| Rule ID | ✅ | Platform-prefixed unique identifier |
| Name | ✅ | Human-readable descriptive name |
| Description | ✅ | What the rule detects and why |
| Severity | ✅ | Threat severity level |
| Detection Logic | ✅ | Query/pattern/signature (platform-specific) |
| MITRE ATT&CK | ✅ | At least one technique ID |
| Compliance | ✅ | At least one regulatory reference |
| Test ID / References | ✅ | Source test catalog ID |
| Tags | ✅ | Categorization keywords |
| Risk Score | ✅ | 1-100 numerical risk rating |

Platform-specific required fields:

| Platform | Additional Required Fields |
|----------|---------------------------|
| Elastic | `type`, `query`, `index`, `interval` |
| Splunk | `search`, `sourcetype`, `action` |
| FortiSIEM | `Pattern`, `EventType` |
| QRadar | `aql_query`, `log_source`, `credibility`, `relevance` |
| Sentinel | `query`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, `tactics`, `techniques` |
| Wazuh | `decoded_as`, `match`, `level`, `group` |
| Zeek | `ip-proto`, `src-ip`, `dst-port`, `payload`, `event` |
| Suricata | `msg`, `content`, `classtype`, `sid`, `rev`, `severity` |
| OCI | `condition`, `actions`, `compartmentId` |
| Azure | `query`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold` |
| AWS | `cloudwatch_metric`, `eventbridge_pattern` |

---

## Pull Request Process

### 1. Pre-Submission Checklist

Before opening a PR, verify:

- [ ] All 11 platform rule files are updated (or exceptions documented)
- [ ] All mapping files are updated (see "How to Update Mappings" below)
- [ ] `validate.sh` passes with zero errors
- [ ] `deploy.sh --dry-run` succeeds for all affected platforms
- [ ] No duplicate rule IDs (use `grep -r "YOUR-RULE-ID" rules/`)
- [ ] Rule names are consistent across platforms
- [ ] Severity and risk score are consistent across platforms
- [ ] MITRE technique IDs are valid (check https://attack.mitre.org/)
- [ ] Compliance references are accurate

### 2. PR Title Format

```
[PLATFORM] [CATEGORY] Brief description
```

Examples:
- `[ALL] [AI] Add prompt injection detection rules for all platforms`
- `[ELASTIC] [WSTG] Fix KQL query syntax in ES-WSTG07-003`
- `[SPLUNK] [MAPPING] Add PCI-DSS 4.0 cross-references for WSTG-04 rules`

### 3. PR Description Template

```markdown
## Summary
Brief description of changes.

## Platforms Affected
- [ ] Elastic
- [ ] Splunk
- [ ] FortiSIEM
- [ ] QRadar
- [ ] Sentinel
- [ ] Wazuh
- [ ] Zeek
- [ ] Suricata
- [ ] OCI
- [ ] Azure
- [ ] AWS

## Categories Affected
- [ ] AI/LLM Security
- [ ] API Security
- [ ] Mobile Security
- [ ] Database Security
- [ ] MITRE ATT&CK
- [ ] Lateral Movement
- [ ] WSTG 01-03
- [ ] WSTG 04-06
- [ ] WSTG 07-09
- [ ] WSTG 10

## New Rules Added
- ES-AI-PI-027 / SPL-AI-PI-027 / ... (list all platform IDs)

## Mappings Updated
- [ ] test-to-siem.json
- [ ] mitre-to-siem.json
- [ ] regulatory-cross-map.json
- [ ] Platform-specific mappings (list)
- [ ] Compliance mappings (list)

## Testing
- [ ] validate.sh passes
- [ ] deploy.sh --dry-run passes for all platforms
- [ ] Manual query verification (list platforms tested)

## Screenshots / Evidence
(If applicable)
```

### 4. Review Process

1. **Automated checks**: `validate.sh` runs on PR creation
2. **Cross-platform review**: At least one reviewer verifies all 11 platforms are represented
3. **Security review**: Reviewer checks detection logic for false positive risk
4. **Mapping review**: Reviewer verifies cross-reference integrity
5. **Approval**: Two approvals required (one platform specialist, one mapping specialist)

---

## Testing Requirements

### Mandatory Tests

1. **Syntax validation**: `jq` for JSON, `xmllint` for XML, manual review for conf/zeek/rules
2. **Script validation**: `./scripts/validate.sh` must pass
3. **Dry-run deployment**: `./scripts/deploy.sh <platform> --dry-run` for each platform

### Recommended Tests

1. **Single-platform query test**: Deploy one rule to a test environment and verify it triggers on known-good test data
2. **False positive test**: Verify the rule does NOT trigger on benign traffic
3. **Cross-platform consistency**: Verify the same test event triggers equivalent rules on multiple platforms
4. **Performance test**: For high-volume rules, measure query execution time and index impact

### Test Data

For testing new rules, consider creating:

```bash
# Generate test events for Elastic
curl -X POST "${ELASTIC_HOST}/logs-test/_doc" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"event.category": "network", "message": "prompt-injection detected"}'

# Generate test events for Splunk
echo '{"time":'$(date +%s)', "event":"prompt-injection detected", "sourcetype":"access_logs"}' | \
  curl -X POST "${SPLUNK_HOST}:8088/services/collector" \
  -H "Authorization: Splunk ${SPLUNK_TOKEN}" \
  -d @-

# For Wazuh, send a test log
echo 'Aug 17 19:00:00 testhost web_log: prompt-injection detected' | \
  /var/ossec/bin/wazuh-logtest
```

---

## Code Review Criteria

Reviewers evaluate PRs on these criteria:

### 1. Detection Logic Quality

- [ ] Query/pattern accurately detects the described threat
- [ ] No excessive false positives (reasonable specificity)
- [ ] No missed detections (reasonable sensitivity)
- [ ] Threshold values are sensible for production environments

### 2. Cross-Platform Consistency

- [ ] Same threat has same severity on all platforms
- [ ] Same test ID maps to all 11 platform rule IDs
- [ ] MITRE technique IDs match across platforms
- [ ] Compliance references match across platforms

### 3. Naming and Formatting

- [ ] Rule IDs follow naming conventions
- [ ] Rule names are consistent across platforms
- [ ] File naming follows category patterns
- [ ] JSON/XML/conf formatting is consistent with existing files

### 4. Mapping Integrity

- [ ] Every new rule ID appears in the corresponding platform mapping file
- [ ] Every new test ID appears in `test-to-siem.json`
- [ ] MITRE techniques are updated in `mitre-to-siem.json`
- [ ] Compliance references are updated in regulatory mapping files
- [ ] `database-to-siem.json` is updated if adding database rules

### 5. Completeness

- [ ] All 11 platforms have the new rule (or documented exception)
- [ ] All relevant category files are updated
- [ ] Container files have updated `total_rules` counts
- [ ] No orphan references (test IDs that don't map to any rule)

---

## Compliance Cross-Reference Requirements

Every rule must have at least one regulatory compliance reference. The 8 supported frameworks are:

| Framework | Prefix | Mapping File | Example Reference |
|-----------|--------|-------------|-------------------|
| PCI-DSS v4.0 | `PCI-DSS-` | `pci-dss-mappings.json` | `PCI-DSS-6.5`, `PCI-DSS-8.5` |
| GDPR | `GDPR-` | `gdpr-mappings.json` | `GDPR-32A-001`, `GDPR-25-012` |
| HIPAA | `HIPAA-` | `hipaa-mappings.json` | `HIPAA-TS-001`, `HIPAA-ADM-006` |
| NIST 800-53 Rev 5 | `NIST-` | `nist-mappings.json` | `NIST-AC-4`, `NIST-SI-10` |
| EU NIS2 Directive | `NIS2-` | `nis2-mappings.json` | `NIS2-Art.15(1)`, `NIS2-Art.21(2)(c)` |
| EU DORA | `DORA-` | `dora-mappings.json` | `DORA-Art.9`, `DORA-Art.11` |
| EU Data Act | `DATA-` | `data-act-mappings.json` | `DATA-Art.6`, `DATA-Art.8` |
| EU AI Act | `AI-ACT-` | `ai-act-mappings.json` | `AI-ACT-15`, `AI-ACT-55` |

### Adding a New Compliance Reference

1. **Identify the control**: Find the specific control number in the framework
2. **Add to the rule**: Include the reference in the `compliance` field on each platform
3. **Update the mapping file**: Add the entry to the framework's mapping file
4. **Update cross-map**: Add the reference to `regulatory-cross-map.json`
5. **Verify**: Ensure the reference appears in all 11 platform rule files

Example: Adding PCI-DSS 4.1 reference to a new rule

```json
// In elastic/ai-security.json
{
  "rule_id": "ES-AI-PI-027",
  "compliance": ["AI-PI-027", "PCI-DSS-4.1", "AI-ACT-15"],
  ...
}

// In mappings/pci-dss-mappings.json, add:
{
  "rule_id": "AI-PI-027",
  "name": "New AI detection",
  "severity": "high",
  "compliance_refs": ["PCI-DSS-4.1"],
  "mitre": ["T1190"]
}

// In mappings/regulatory-cross-map.json, add to the existing entry:
{
  "test_id": "AI-PI-027",
  "regulatory": {
    "pci_dss": ["4.1"],
    ...
  }
}
```

---

## How to Update Mappings When Adding Rules

When adding a new rule, you must update **all** relevant mapping files. Here is the complete checklist:

### Step 1: Add to test-to-siem.json

```json
{
  "test_id": "AI-PI-027",
  "test_name": "New AI Detection",
  "siem_rules": {
    "elastic": "ES-AI-PI-027",
    "splunk": "SPL-AI-PI-027",
    "fortisiem": "FSIEM-AI-PI-027",
    "qradar": "QR-AI-PI-027",
    "sentinel": "MS-AI-PI-027",
    "wazuh": "WZ-AIPI027",
    "zeek": "ZK-AIPI027",
    "suricata": "SUR-AI-PI-027",
    "oracle": "OCI-AI-PI-027",
    "azure": "AZ-AI-PI-027",
    "aws": "AWS-AI-PI-027"
  },
  "category": "ai-security",
  "severity": "critical"
}
```

### Step 2: Add to each platform-specific mapping file

Add entries to all 11 mapping files:
- `elastic-mappings.json`
- `splunk-mappings.json`
- `fortisiem-mappings.json`
- `qradar-mappings.json`
- `sentinel-mappings.json`
- `wazuh-mappings.json`
- `zeek-mappings.json`
- `suricata-mappings.json`
- `oracle-mappings.json`
- `azure-mappings.json`
- `aws-mappings.json`

Example for `elastic-mappings.json`:
```json
{
  "rule_id": "ES-AI-PI-027",
  "test_id": "AI-PI-027",
  "name": "New AI Detection",
  "category": "ai-security",
  "severity": "critical",
  "mitre": ["T1190"]
}
```

### Step 3: Add to mitre-to-siem.json

If the rule covers a MITRE technique:

```json
{
  "T1190": [
    // ... existing entries ...
    {
      "rule_id": "AI-PI-027",
      "name": "New AI Detection",
      "category": "ai-security",
      "severity": "critical"
    }
  ]
}
```

### Step 4: Add to relevant regulatory mapping files

For each compliance framework the rule relates to:
- `pci-dss-mappings.json`
- `gdpr-mappings.json`
- `hipaa-mappings.json`
- `nist-mappings.json`
- `nis2-mappings.json`
- `dora-mappings.json`
- `data-act-mappings.json`
- `ai-act-mappings.json`

### Step 5: Add to regulatory-cross-map.json

Update the cross-map entry for the test ID:

```json
{
  "test_id": "AI-PI-027",
  "regulatory": {
    "pci_dss": ["4.1"],
    "gdpr": ["Art. 32"],
    "hipaa": ["§164.312(a)(1)"],
    "nist_800_53": ["SI-10"],
    "nis2": ["Art. 15(1)"],
    "dora": ["Art. 9"],
    "data_act": ["Art. 6"],
    "ai_act": ["Art. 15"]
  },
  "mitre": ["T1190"],
  "severity": "critical"
}
```

### Step 6: Add to database-to-siem.json (if applicable)

If the rule is database-specific:

```json
{
  "postgresql": [
    // ... existing entries ...
    {
      "rule_id": "DB-PG-004",
      "name": "PostgreSQL — New Detection",
      "severity": "high"
    }
  ]
}
```

### Step 7: Update total_rules count

Update the `total_rules` count in each affected rule file's container object. For example, in `elastic/ai-security.json`, increment `total_rules` by the number of rules added.

### Step 8: Validate

```bash
./scripts/validate.sh
./scripts/deploy.sh all --dry-run
```

Verify:
- [ ] Every test ID in `test-to-siem.json` has all 11 platform rule IDs
- [ ] Every rule ID in `rules/` appears in the corresponding `mappings/` file
- [ ] Every MITRE technique in a rule appears in `mitre-to-siem.json`
- [ ] Every compliance reference appears in the relevant regulatory mapping
- [ ] `total_rules` counts match the actual number of rules in each file

---

## Summary of File Responsibilities

When adding N new rules to category C:

| File | Action |
|------|--------|
| `rules/elastic/C.json` | Add N rule objects |
| `rules/splunk/C.conf` | Add N stanzas |
| `rules/fortisiem/C.xml` | Add N `<Rule>` elements |
| `rules/qradar/C.json` | Add N rule objects |
| `rules/sentinel/C.json` | Add N rule objects |
| `rules/wazuh/C.xml` | Add N `<rule>` elements |
| `rules/zeek/C.zeek` | Add N signatures |
| `rules/suricata/C.rules` | Add N rule lines |
| `rules/oracle/C.json` | Add N rule objects |
| `rules/azure/C.json` | Add N rule objects |
| `rules/aws/C.json` | Add N rule objects |
| `mappings/test-to-siem.json` | Add N test ID entries |
| `mappings/elastic-mappings.json` | Add N entries |
| `mappings/splunk-mappings.json` | Add N entries |
| `mappings/fortisiem-mappings.json` | Add N entries |
| `mappings/qradar-mappings.json` | Add N entries |
| `mappings/sentinel-mappings.json` | Add N entries |
| `mappings/wazuh-mappings.json` | Add N entries |
| `mappings/zeek-mappings.json` | Add N entries |
| `mappings/suricata-mappings.json` | Add N entries |
| `mappings/oracle-mappings.json` | Add N entries |
| `mappings/azure-mappings.json` | Add N entries |
| `mappings/aws-mappings.json` | Add N entries |
| `mappings/mitre-to-siem.json` | Add/update MITRE technique entries |
| `mappings/regulatory-cross-map.json` | Add N cross-map entries |
| `mappings/{relevant-framework}-mappings.json` | Add entries per framework |
| `mappings/database-to-siem.json` | Add entries (if database rules) |

That's a minimum of **22 files** to update for each new rule set. This ensures complete cross-reference integrity across all platforms and frameworks.