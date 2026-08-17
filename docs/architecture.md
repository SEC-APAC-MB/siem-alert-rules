# Architecture Guide

## Overview

The SIEM Alert Rules repository provides **20,000+ production-ready detection rules** across **11 SIEM and cloud security platforms**, mapped from **10,426+ security test checks** covering OWASP WSTG, API Security, Mobile Security, AI/LLM Security, MITRE ATT&CK, lateral movement chains, database security, and 8 regulatory compliance frameworks.

The architecture is designed around a single principle: **same threat, different query language**. Every detection concept — whether it's a direct prompt injection attack or a PostgreSQL privilege escalation — is expressed natively on each platform while preserving identical semantic meaning, severity, and cross-references.

### Repository Structure

```
siem-alert-rules/
├── rules/                    # Platform-specific rule files
│   ├── elastic/              # KQL/EQL + Rule API JSON
│   ├── splunk/               # SPL + correlation searches (.conf)
│   ├── fortisiem/            # Pattern-based XML
│   ├── qradar/               # AQL + custom rules (JSON)
│   ├── sentinel/             # KQL analytics rules (JSON)
│   ├── wazuh/                # Custom rules (XML)
│   ├── zeek/                 # Zeek script signatures (.zeek)
│   ├── suricata/             # Emerging threats + custom (.rules)
│   ├── oracle/               # OCI Alarm + Event rules (JSON)
│   ├── azure/                # Azure Monitor + Policy (JSON)
│   └── aws/                  # CloudWatch + EventBridge + GuardDuty (JSON)
├── mappings/                 # Cross-reference mapping files
│   ├── test-to-siem.json     # Master test → 11-platform rule ID map
│   ├── mitre-to-siem.json    # MITRE ATT&CK → SIEM rule map
│   ├── regulatory-cross-map.json  # All-to-all cross map
│   ├── elastic-mappings.json  # Platform-specific ID mapping
│   ├── splunk-mappings.json
│   ├── fortisiem-mappings.json
│   ├── qradar-mappings.json
│   ├── sentinel-mappings.json
│   ├── wazuh-mappings.json
│   ├── zeek-mappings.json
│   ├── suricata-mappings.json
│   ├── oracle-mappings.json
│   ├── azure-mappings.json
│   ├── aws-mappings.json
│   ├── pci-dss-mappings.json
│   ├── gdpr-mappings.json
│   ├── hipaa-mappings.json
│   ├── nist-mappings.json
│   ├── nis2-mappings.json
│   ├── dora-mappings.json
│   ├── data-act-mappings.json
│   ├── ai-act-mappings.json
│   └── database-to-siem.json
├── scripts/
│   ├── validate.sh            # Validate all rules across platforms
│   └── deploy.sh             # Deploy rules to target platforms
├── docs/
│   ├── architecture.md        # This file
│   ├── deployment-guide.md
│   └── contributing.md
├── generate_all.py           # Master generator
├── generate_rules.py         # Original generator
└── README.md
```

---

## 11-Platform Architecture

| # | Platform | Rule Prefix | File Format | Directory | Approx. Rules |
|---|----------|-------------|-------------|-----------|---------------|
| 1 | Elastic Security (Kibana) | `ES-` | JSON (KQL/EQL) | `rules/elastic/` | 2,500+ |
| 2 | Splunk Enterprise | `SPL-` | `.conf` (SPL) | `rules/splunk/` | 2,500+ |
| 3 | FortiSIEM | `FSIEM-` | XML | `rules/fortisiem/` | 2,500+ |
| 4 | IBM QRadar | `QR-` | JSON (AQL) | `rules/qradar/` | 2,500+ |
| 5 | Microsoft Sentinel | `MS-` | JSON (KQL) | `rules/sentinel/` | 2,500+ |
| 6 | Wazuh | `WZ-` | XML | `rules/wazuh/` | 2,500+ |
| 7 | Zeek (Bro) | `ZK-` | `.zeek` signatures | `rules/zeek/` | 2,500+ |
| 8 | Suricata | `SUR-` | `.rules` | `rules/suricata/` | 2,500+ |
| 9 | Oracle Cloud Infrastructure | `OCI-` | JSON (OCI Alarms) | `rules/oracle/` | 2,000+ |
| 10 | Microsoft Azure | `AZ-` | JSON (KQL/ARM) | `rules/azure/` | 2,000+ |
| 11 | AWS | `AWS-` | JSON (CloudWatch/EventBridge/GuardDuty) | `rules/aws/` | 2,000+ |

### Rule ID Conventions

Rule IDs follow a strict prefix convention tied to the platform:

| Platform | Prefix | Example | Pattern |
|----------|--------|---------|---------|
| Elastic Security | `ES-` | `ES-AI-PI-001`, `ES-WSTG01-001` | `ES-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |
| Splunk | `SPL-` | `SPL-AI-PI-001`, `SPL-WSTG01-001` | `SPL-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |
| FortiSIEM | `FSIEM-` | `FSIEM-AI-PI-001`, `FSIEM-WSTG04-001` | `FSIEM-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |
| QRadar | `QR-` | `QR-AI-PI-001`, `QR-WSTG01-001` | `QR-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |
| Sentinel | `MS-` | `MS-AI-PI-001`, `MS-WSTG01-001` | `MS-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |
| Wazuh | `WZ-` | `WZ-AIPI001`, `WZ-WSTG01001` | `WZ-{CATEGORY}{NUMBER}` (no hyphens in IDs) |
| Zeek | `ZK-` | `ZK-API001`, `ZK-LM001` | `ZK-{CATEGORY}{NUMBER}` |
| Suricata | `SUR-` | `SUR-AI-PI-001`, `SUR-WSTG01-001` | `SUR-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |
| OCI | `OCI-` | `OCI-DB-PG-001`, `OCI-WSTG01-001` | `OCI-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |
| Azure | `AZ-` | `AZ-AI-PI-001`, `AZ-WSTG01-001` | `AZ-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |
| AWS | `AWS-` | `AWS-AI-PI-001`, `AWS-WSTG01-001` | `AWS-{CATEGORY}-{SUBCATEGORY}-{NUMBER}` |

**Category abbreviations used in IDs:**

| Abbreviation | Category |
|-------------|----------|
| `WSTG01`–`WSTG10` | OWASP WSTG catalogs (01-03, 04-06, 07-09, 10-business-logic) |
| `AI` | AI/LLM Security |
| `PI` | Prompt Injection |
| `DEX` | Data Exfiltration (AI) |
| `MDL` | Model Integrity (AI) |
| `RAG` | RAG Pipeline (AI) |
| `HAL` | Hallucination (AI) |
| `BIA` | Bias Detection (AI) |
| `GOV` | Governance (AI) |
| `RED` | Red Team (AI) |
| `SAF` | Safety (AI) |
| `VEC` | Vector DB (AI) |
| `API` | API Security (OWASP API Top 10) |
| `MOB` | Mobile Security (MASVS) |
| `DB` | Database Security |
| `LM` | Lateral Movement |
| `MITRE` | MITRE ATT&CK |

---

## Category Coverage

### OWASP WSTG (Web Security Testing Guide) — Catalogs 01–10

| WSTG Catalog | Categories Covered | Rules per Platform |
|-------------|---------------------|-------------------|
| WSTG-01 (Information Gathering) | Reconnaissance, DNS, fingerprinting, metadata | ~20 |
| WSTG-02 (Configuration Management) | Server config, app architecture, cloud misconfigs | ~15 |
| WSTG-03 (Identity Management) | Auth bypass, session management, JWT | ~25 |
| WSTG-04 (Authentication Testing) | Default creds, brute force, MFA bypass, credential stuffing | ~20 |
| WSTG-05 (Authorization Testing) | BOLA, privilege escalation, IDOR | ~15 |
| WSTG-06 (Session Management) | Cookie security, token fixation, cache issues | ~15 |
| WSTG-07 (Input Validation) | XSS, SQLi, command injection, SSRF | ~20 |
| WSTG-08 (Error Handling) | Stack traces, verbose errors, info disclosure | ~10 |
| WSTG-09 (Cryptography) | Weak TLS, certificate issues, insecure hashing | ~15 |
| WSTG-10 (Business Logic) | Race conditions, parameter tampering, workflow bypass | ~20 |

File mapping:
- `wstg-01-03.json/.conf/.xml/.zeek/.rules` — WSTG catalogs 01, 02, 03
- `wstg-04-06.json/.conf/.xml/.zeek/.rules` — WSTG catalogs 04, 05, 06
- `wstg-07-09.json/.conf/.xml/.zeek/.rules` — WSTG catalogs 07, 08, 09
- `wstg-10-business-logic.json/.conf/.xml/.zeek/.rules` — WSTG catalog 10

### AI/LLM Security — 1,691 tests, 3,382 rules

Covers prompt injection (direct, indirect, multi-turn), data exfiltration, model poisoning, RAG pipeline attacks, hallucination detection, bias detection, AI governance, red team attacks, safety violations, and vector database security (Pinecone, Weaviate, ChromaDB, Qdrant, Milvus).

### API Security (OWASP API Top 10) — 327 tests

Covers broken object-level authorization, broken authentication, BOPA, unrestricted resource consumption, broken function-level authorization, unrestricted business flow access, SSRF, security misconfiguration, improper inventory, unsafe consumption of third-party APIs.

### Mobile Security (MASVS) — 239 tests

Covers insecure data storage, network communication, authentication, jailbreak/root detection, intent interception, cryptographic misuse, code tampering, reverse engineering.

### MITRE ATT&CK — 276 techniques

Enterprise tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration, Impact.

### Lateral Movement Chains — 161 tests

Pass-the-hash, pass-the-ticket, RDP anomalies, SSH lateral movement, WMI/PSExec, SMB admin shares, DCOM lateral movement, Kerberoasting, LLMNR/NBT-NS poisoning.

### Database Security — 24 databases, 30 core rules

| Type | Databases |
|------|-----------|
| SQL | PostgreSQL, MySQL, SQL Server, Oracle, SQLite |
| NoSQL | MongoDB, DynamoDB, Cassandra, CouchDB, Firestore |
| Graph | Neo4j, ArangoDB, Amazon Neptune |
| Time-series | InfluxDB, TimescaleDB, Prometheus |
| Vector | Pinecone, Weaviate, Milvus, ChromaDB, Qdrant |
| Key-value | Redis, Memcached |
| Column-family | HBase |

---

## Cross-Platform Detection Logic Mapping

The same threat concept is expressed natively on each platform. Consider the rule for **Direct Prompt Injection (AI-PI-001)**:

### Elastic Security (KQL)

```json
{
  "rule_id": "ES-AI-PI-001",
  "name": "AI — Direct Prompt Injection",
  "severity": "critical",
  "type": "query",
  "query": "event.category:(\"network\" OR \"authentication\" OR \"database\" OR \"iam\") AND (\"prompt-injection\" OR \"direct\" OR \"llm\")",
  "risk_score": 90,
  "interval": "5m"
}
```

### Splunk (SPL)

```ini
[SPL-AI-PI-001]
name = AI — Direct Prompt Injection
severity = critical
search = index=* ("prompt-injection" OR "direct" OR "llm") | stats count, values(src_ip) as src_ips, values(dest_ip) as dest_ips by rule_id, rule_name | where count > 5
risk_score = 90
```

### FortiSIEM (XML)

```xml
<Rule name="FSIEM-AI-PI-001" id="FSIEM-AI-PI-001">
  <Description>Detects direct prompt injection attempts overriding system instructions via user input</Description>
  <Severity>Critical</Severity>
  <Pattern>"prompt-injection" OR "direct"</Pattern>
  <EventType>PROMPT_INJECTION</EventType>
  <MITRE>T1190</MITRE>
  <Compliance>AI-PI-001,AI-ACT-15</Compliance>
</Rule>
```

### QRadar (AQL)

```json
{
  "rule_id": "QR-AI-PI-001",
  "severity": 9,
  "aql_query": "SELECT sourceip, destinationip, URL, payload FROM events WHERE (payload ILIKE '%prompt-injection%' OR payload ILIKE '%direct%') GROUP BY sourceip, destinationip, URL LAST 15 MINUTES",
  "credibility": 7,
  "relevance": 9
}
```

### Microsoft Sentinel (KQL)

```json
{
  "rule_id": "MS-AI-PI-001",
  "severity": "High",
  "query": "let threshold = 5;\nprompt_injection_events\n| where prompt_injection has_any(\"ai\", \"prompt-injection\", \"direct\", \"llm\")\n| summarize count() by SourceIP, bin(TimeGenerated, 5m)\n| where count_ > threshold",
  "queryFrequency": "PT5M",
  "triggerOperator": "GreaterThan",
  "triggerThreshold": 5
}
```

### Wazuh (XML)

```xml
<rule id="WZ-AIPI001" level="9" group="ai,prompt-injection,direct">
  <description>AI — Direct Prompt Injection</description>
  <decoded_as>web_log</decoded_as>
  <field name="test_id">AI-PI-001</field>
  <mitre><id>T1190</id></mitre>
  <match>prompt-injection|direct</match>
</rule>
```

### Zeek (Signature)

```zeek
signature ZK-AIPI001 {
  ip-proto tcp
  src-ip $HOME_NET
  dst-port 80 443 8080 8443
  payload /prompt-injection|direct/
  event "Detect_AI_Direct_Prompt_Injection"
}
```

### Suricata (Rules)

```
SUR-AI-PI-001 http any any -> $HOME_NET any (msg:"SIEM AI — Direct Prompt Injection"; content:"prompt-injection"; content:"direct"; classtype:attempted-admin; sid:3000000; rev:1; severity:1; metadata:mitre T1190;)
```

### Oracle Cloud Infrastructure (OCI Alarm)

```json
{
  "rule_id": "OCI-AI-PI-001",
  "severity": "CRITICAL",
  "condition": {
    "eventType": ["com.oracle.cloud.monitoring"],
    "compartmentId": "$COMPARTMENT_ID",
    "metric": "prompt_injection",
    "operator": "GT",
    "threshold": 5
  },
  "actions": [{"actionType": "ONS", "description": "Send alert notification"}]
}
```

### Azure (KQL Monitor Query)

```json
{
  "rule_id": "AZ-AI-PI-001",
  "severity": 0,
  "query": "AzureDiagnostics | where Category contains 'prompt_injection' | summarize count() by bin(TimeGenerated, 5m), resource_group | where count_ > 5",
  "queryFrequency": "PT5M",
  "triggerOperator": "GreaterThan",
  "triggerThreshold": 5
}
```

### AWS (CloudWatch + EventBridge)

```json
{
  "rule_id": "AWS-AI-PI-001",
  "severity": "critical",
  "cloudwatch_metric": {
    "namespace": "SIEM/Security",
    "metricName": "prompt_injection",
    "dimensions": {"RuleId": "AWS-AI-PI-001"},
    "threshold": 5,
    "comparisonOperator": "GreaterThanThreshold"
  },
  "eventbridge_pattern": {
    "source": ["aws.security", "aws.guardduty", "aws.cloudtrail"],
    "detail-type": ["AWS API Call via CloudTrail", "GuardDuty Finding"]
  },
  "guardduty_finding": {"severity": 9, "type": "PROMPT_INJECTION"}
}
```

---

## Cross-Mapping System

The cross-mapping system links four dimensions:

```
test_id → siem_rules (11 platforms) → regulatory_controls (8 frameworks) → MITRE ATT&CK techniques
```

### test-to-siem.json (Master Mapping)

Every test ID maps to exactly one rule ID per platform:

```json
{
  "test_id": "AI-PI-001",
  "test_name": "Direct Prompt Injection",
  "siem_rules": {
    "elastic": "ES-AI-PI-001",
    "splunk": "SPL-AI-PI-001",
    "fortisiem": "FSIEM-AI-PI-001",
    "qradar": "QR-AI-PI-001",
    "sentinel": "MS-AI-PI-001",
    "wazuh": "WZ-AIPI001",
    "zeek": "ZK-AIPI001",
    "suricata": "SUR-AI-PI-001",
    "oracle": "OCI-AI-PI-001",
    "azure": "AZ-AI-PI-001",
    "aws": "AWS-AI-PI-001"
  },
  "category": "ai-security",
  "severity": "critical"
}
```

### Platform-Specific Mappings

Each platform has its own mapping file (e.g., `elastic-mappings.json`, `splunk-mappings.json`) containing:

```json
{
  "rule_id": "ES-WSTG01-001",
  "test_id": "WSTG01-001",
  "name": "Search Engine Discovery of Sensitive Content",
  "category": "wstg-01-03",
  "severity": "low",
  "mitre": ["T1595", "T1592"]
}
```

### Regulatory Cross-Mapping (regulatory-cross-map.json)

Maps every test ID to all 8 compliance frameworks:

```json
{
  "test_id": "AI-PI-001",
  "regulatory": {
    "pci_dss": ["3.5", "6.5"],
    "gdpr": ["Art. 32", "Art. 35"],
    "hipaa": ["§164.312(a)(1)", "§164.312(b)"],
    "nist_800_53": ["SI-10", "SC-5"],
    "nis2": ["Art. 15(1)", "Art. 21(2)(c)"],
    "dora": ["Art. 9", "Art. 11"],
    "data_act": ["Art. 6", "Art. 8"],
    "ai_act": ["Art. 15", "Art. 55"]
  },
  "mitre": ["T1190", "T1078"],
  "severity": "critical"
}
```

### Individual Regulatory Mappings

| File | Framework | Coverage |
|------|-----------|----------|
| `pci-dss-mappings.json` | PCI-DSS v4.0 | 406 test IDs → 812+ rule mappings |
| `gdpr-mappings.json` | GDPR | 266 test IDs → 532+ rule mappings |
| `hipaa-mappings.json` | HIPAA | 288 test IDs → 576+ rule mappings |
| `nist-mappings.json` | NIST 800-53 Rev 5 | 367 test IDs → 734+ rule mappings |
| `nis2-mappings.json` | EU NIS2 Directive | 367 test IDs → 734+ rule mappings |
| `dora-mappings.json` | EU DORA | 241 test IDs → 482+ rule mappings |
| `data-act-mappings.json` | EU Data Act | 268 test IDs → 536+ rule mappings |
| `ai-act-mappings.json` | EU AI Act | 311 test IDs → 622+ rule mappings |

### MITRE ATT&CK Mapping (mitre-to-siem.json)

Maps each MITRE technique to the test IDs and SIEM rules that detect it:

```json
{
  "T1595": [
    {
      "rule_id": "WSTG01-001",
      "name": "Search Engine Discovery of Sensitive Content",
      "category": "wstg-01-03",
      "severity": "low"
    }
  ]
}
```

### Database-to-SIEM Mapping (database-to-siem.json)

Maps database-specific detections across all platforms:

```json
{
  "postgresql": [
    {"rule_id": "DB-PG-001", "name": "PostgreSQL — Privilege Escalation via SET ROLE", "severity": "critical"},
    {"rule_id": "DB-PG-002", "name": "PostgreSQL — pg_dump Data Exfiltration", "severity": "high"}
  ]
}
```

---

## Rule Structure Per Platform

### Elastic Security (JSON)

```json
{
  "rule_id": "ES-AI-PI-001",           // Required. Format: ES-{CATEGORY}-{NUMBER}
  "name": "AI — Direct Prompt Injection", // Required. Human-readable name
  "description": "Detects ...",          // Required. What the rule detects
  "severity": "critical",                // Required. critical|high|medium|low|informational
  "type": "query",                       // Required. query|eql|threshold|machine_learning
  "query": "event.category:...",          // Required. KQL or EQL query string
  "index": ["logs-*"],                   // Required. Target index patterns
  "references": ["AI-PI-001"],           // Required. Source test ID(s)
  "mitre": ["T1190"],                    // Required. MITRE ATT&CK technique IDs
  "compliance": ["AI-PI-001", "AI-ACT-15"], // Required. Regulatory references
  "tags": ["ai", "prompt-injection"],    // Required. Categorization tags
  "risk_score": 90,                       // Required. 1-100 risk score
  "interval": "5m"                        // Optional. Query interval (default: 5m)
}
```

**Container format:**
```json
{
  "description": "Elastic Security SIEM alert rules — {category}",
  "version": "1.0.0",
  "elastic_version": "8.x",
  "total_rules": 27,
  "rules": [ /* ... */ ]
}
```

### Splunk (INI/conf format)

```ini
[SPL-AI-PI-001]                            # Required. Stanza = rule ID
name = AI — Direct Prompt Injection         # Required
description = Detects ...                   # Required
severity = critical                          # Required. critical|high|medium|low|informational
search = index=* ("prompt-injection" ...)   # Required. SPL search query
sourcetype = access_logs,auth_logs,firewall  # Required. Source types
action = email                               # Required. Alert action
references = AI-PI-001                       # Required
mitre = T1190                                # Required
compliance = AI-PI-001,AI-ACT-15             # Required
risk_score = 90                              # Required
```

### FortiSIEM (XML)

```xml
<Rule name="FSIEM-AI-PI-001" id="FSIEM-AI-PI-001">
  <Description>Detects direct prompt injection attempts...</Description>  <!-- Required -->
  <Severity>Critical</Severity>                                           <!-- Required. Critical|High|Medium|Low|Info -->
  <Pattern>"prompt-injection" OR "direct"</Pattern>                       <!-- Required. Pattern expression -->
  <EventType>PROMPT_INJECTION</EventType>                                <!-- Required. Event classification -->
  <MITRE>T1190</MITRE>                                                   <!-- Required -->
  <Compliance>AI-PI-001,AI-ACT-15</Compliance>                           <!-- Required -->
</Rule>
```

**Container:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- FortiSIEM Pattern Rules — {category} -->
<!-- Total rules: N -->
<Rules>
  <!-- ... rule elements ... -->
</Rules>
```

### QRadar (JSON with AQL)

```json
{
  "rule_id": "QR-AI-PI-001",           // Required. Format: QR-{CATEGORY}-{NUMBER}
  "name": "AI — Direct Prompt Injection", // Required
  "description": "Detects ...",           // Required
  "severity": 9,                          // Required. 1-10 (QRadar severity scale)
  "aql_query": "SELECT ... FROM events WHERE ...", // Required. AQL query
  "log_source": "APPLICATION_LOG",        // Required. QRadar log source type
  "references": ["AI-PI-001"],            // Required
  "mitre": {                              // Required
    "tactic": "Initial Access",
    "technique": "T1190"
  },
  "compliance": ["AI-PI-001", "AI-ACT-15"], // Required
  "credibility": 7,                        // Optional. 1-10 (default: 7)
  "relevance": 9                           // Optional. 1-10 (default: based on severity)
}
```

**Container format:**
```json
{
  "version": "1.0.0",
  "generated": "2026-08-17",
  "description": "QRadar SIEM alert rules — {category}",
  "total_rules": 27,
  "rules": [ /* ... */ ]
}
```

### Microsoft Sentinel (JSON with KQL)

```json
{
  "rule_id": "MS-AI-PI-001",            // Required. Format: MS-{CATEGORY}-{NUMBER}
  "name": "AI — Direct Prompt Injection", // Required
  "description": "Detects ...",            // Required
  "severity": "High",                      // Required. High|Medium|Low|Informational
  "query": "let threshold = 5;\n...",     // Required. KQL analytics query
  "queryFrequency": "PT5M",               // Required. ISO 8601 duration
  "queryPeriod": "PT5M",                   // Required. ISO 8601 duration
  "triggerOperator": "GreaterThan",        // Required
  "triggerThreshold": 5,                   // Required
  "tactics": ["InitialAccess"],            // Required. MITRE tactics
  "techniques": ["T1190"],                // Required. MITRE techniques
  "references": ["AI-PI-001"],            // Required
  "compliance": ["AI-PI-001", "AI-ACT-15"], // Required
  "tags": ["ai", "prompt-injection"],      // Required
  "risk_score": 90                          // Required. 1-100
}
```

### Wazuh (XML)

```xml
<rule id="WZ-AIPI001" level="9" group="ai,prompt-injection,direct">
  <description>AI — Direct Prompt Injection — Detects ...</description>  <!-- Required -->
  <decoded_as>web_log</decoded_as>                                       <!-- Required -->
  <field name="test_id">AI-PI-001</field>                                <!-- Required -->
  <mitre><id>T1190</id></mitre>                                         <!-- Required -->
  <match>prompt-injection|direct</match>                                 <!-- Required -->
</rule>
```

**Wazuh-specific notes:**
- Rule IDs use compact format without hyphens in sub-IDs: `WZ-AIPI001`, `WZ-WSTG01001`
- `level` maps to severity: 9-10 = critical, 7-8 = high, 5-6 = medium, 3-4 = low, 0-2 = informational
- `group` contains comma-separated tags
- Container wraps rules in `<group name="wazuh,{category},security">`

### Zeek (Signatures)

```zeek
signature ZK-AIPI001 {
  ip-proto tcp               # Required. Protocol
  src-ip $HOME_NET           # Required. Source network
  dst-port 80 443 8080 8443  # Required. Destination ports
  payload /prompt-injection|direct/  # Required. Pattern match
  event "Detect_AI_Direct_Prompt_Injection"  # Required. Event name
}
```

**Zeek-specific notes:**
- Uses compact IDs: `ZK-AIPI001`, `ZK-API001`, `ZK-LM001`
- Payload uses regex patterns with `/pattern/`
- File extension is `.zeek`
- Deployed to `/opt/zeek/share/zeek/site/`

### Suricata (Rules)

```
SUR-AI-PI-001 http any any -> $HOME_NET any (msg:"SIEM AI — Direct Prompt Injection"; content:"prompt-injection"; content:"direct"; classtype:attempted-admin; sid:3000000; rev:1; severity:1; metadata:mitre T1190;)
```

**Suricata-specific notes:**
- Uses standard Suricata rule format with protocol, source/destination, rule options
- `sid` values start at 3000000 for custom rules
- `severity`: 1 = critical, 2 = high, 3 = medium, 4 = low
- `classtype`: attempted-admin, attempted-recon, policy-violation, etc.
- `metadata` includes MITRE technique reference

### Oracle Cloud Infrastructure (JSON)

```json
{
  "rule_id": "OCI-DB-PG-001",            // Required. Format: OCI-{CATEGORY}-{NUMBER}
  "name": "PostgreSQL — Privilege Escalation via SET ROLE",
  "description": "Detects ...",            // Required
  "severity": "CRITICAL",                  // Required. CRITICAL|HIGH|MEDIUM|LOW|INFO
  "condition": {                           // Required. OCI Alarm condition
    "eventType": ["com.oracle.cloud.monitoring"],
    "compartmentId": "$COMPARTMENT_ID",    // Placeholder, replaced on deploy
    "metric": "postgresql",
    "operator": "GT",
    "threshold": 5
  },
  "actions": [{"actionType": "ONS", "description": "Send alert notification"}], // Required
  "references": ["PCI-DSS-8.5"],           // Required
  "mitre": ["T1548"],                      // Required
  "tags": ["database", "postgresql", "privilege-escalation"] // Required
}
```

### Azure (JSON with KQL Monitor Queries)

```json
{
  "rule_id": "AZ-AI-PI-001",            // Required. Format: AZ-{CATEGORY}-{NUMBER}
  "name": "AI — Direct Prompt Injection", // Required
  "description": "Detects ...",            // Required (not shown in excerpt, but present)
  "severity": 0,                           // Required. 0=Critical, 1=High, 2=Medium, 3=Low, 4=Informational
  "query": "AzureDiagnostics | where ...", // Required. KQL query
  "queryFrequency": "PT5M",                // Required. ISO 8601 duration
  "queryPeriod": "PT5M",                   // Required
  "triggerOperator": "GreaterThan",        // Required
  "triggerThreshold": 5,                   // Required
  "tactics": ["T1190"],                    // Required
  "compliance": ["AI-PI-001", "AI-ACT-15"], // Required
  "tags": ["ai", "prompt-injection"],      // Required
  "risk_score": 90                          // Required
}
```

### AWS (JSON with CloudWatch/EventBridge/GuardDuty)

```json
{
  "rule_id": "AWS-AI-PI-001",            // Required. Format: AWS-{CATEGORY}-{NUMBER}
  "name": "AI — Direct Prompt Injection", // Required
  "description": "Detects ...",            // Required
  "severity": "critical",                  // Required. critical|high|medium|low|informational
  "cloudwatch_metric": {                   // Required. CloudWatch metric alarm definition
    "namespace": "SIEM/Security",
    "metricName": "prompt_injection",
    "dimensions": {"RuleId": "AWS-AI-PI-001"},
    "statistic": "Sum",
    "period": 300,
    "evaluationPeriods": 1,
    "threshold": 5,
    "comparisonOperator": "GreaterThanThreshold"
  },
  "eventbridge_pattern": {                 // Required. EventBridge event pattern
    "source": ["aws.security", "aws.guardduty"],
    "detail-type": ["AWS API Call via CloudTrail", "GuardDuty Finding"],
    "detail": {"eventSource": [...], "eventName": [...]}
  },
  "guardduty_finding": {                   // Optional. GuardDuty finding class
    "severity": 9,
    "type": "PROMPT_INJECTION"
  },
  "references": ["AI-PI-001", "AI-ACT-15"], // Required
  "mitre": ["T1190"],                      // Required
  "tags": ["ai", "prompt-injection"],      // Required
  "risk_score": 90                          // Required
}
```

---

## Severity Levels and Risk Scores

### Severity Mapping Across Platforms

| Standard Level | Elastic | Splunk | FortiSIEM | QRadar | Sentinel | Wazuh (level) | Suricata (severity) | OCI | Azure | Risk Score |
|---------------|---------|--------|-----------|--------|----------|---------------|--------------------|----|-------|------------|
| Critical | critical | critical | Critical | 9-10 | High | 9-10 | 1 | CRITICAL | 0 | 81-100 |
| High | high | high | High | 7-8 | Medium | 7-8 | 2 | HIGH | 1 | 61-80 |
| Medium | medium | medium | Medium | 5-6 | Low | 5-6 | 3 | MEDIUM | 2 | 31-60 |
| Low | low | low | Low | 3-4 | Informational | 3-4 | 4 | LOW | 3 | 11-30 |
| Informational | informational | informational | Info | 1-2 | Informational | 0-2 | — | INFO | 4 | 1-10 |

### Risk Score Guidelines

| Range | Classification | Example Use |
|-------|---------------|-------------|
| 81–100 | Critical | Prompt injection, data exfiltration, SQL injection, privilege escalation |
| 61–80 | High | Authentication bypass, SSRF, IDOR, weak crypto |
| 31–60 | Medium | Information disclosure, directory listing, missing headers |
| 11–30 | Low | Verbose errors, fingerprinting, metadata exposure |
| 1–10 | Informational | Reconnaissance, server version disclosure |

---

## How to Add New Rules

### 1. Define the Test ID

Every new rule starts with a canonical test ID in the source catalog:

```
AI-PI-027   (AI → Prompt Injection → #027)
WSTG07-015  (WSTG catalog 07 → test #015)
DB-PG-004   (Database → PostgreSQL → #004)
LM-011      (Lateral Movement → #011)
```

### 2. Create Rules for All 11 Platforms

Each platform must express the same detection concept natively. For each platform, add a rule entry to the appropriate category file:

| Category File | Categories |
|--------------|-----------|
| `ai-security.*` | AI/LLM security |
| `api-security.*` | API security (OWASP API Top 10) |
| `mobile-security.*` | Mobile security (MASVS) |
| `database-security.*` | Database security (24 databases) |
| `mitre-attack.*` | MITRE ATT&CK techniques |
| `lateral-movement.*` | Lateral movement chains |
| `wstg-01-03.*` | WSTG catalogs 01, 02, 03 |
| `wstg-04-06.*` | WSTG catalogs 04, 05, 06 |
| `wstg-07-09.*` | WSTG catalogs 07, 08, 09 |
| `wstg-10-business-logic.*` | WSTG catalog 10 |

### 3. Add Cross-Mappings

Update these mapping files:

1. **`mappings/test-to-siem.json`** — Add the test ID → 11-platform rule ID mapping
2. **`mappings/{platform}-mappings.json`** — Add entry to each of the 11 platform-specific mapping files
3. **`mappings/mitre-to-siem.json`** — If the rule covers a MITRE technique, add/update the mapping
4. **`mappings/regulatory-cross-map.json`** — Add regulatory control references
5. **`mappings/{framework}-mappings.json`** — Add entries to applicable compliance framework mappings (PCI-DSS, GDPR, HIPAA, NIST, NIS2, DORA, Data Act, AI Act)
6. **`mappings/database-to-siem.json`** — If the rule is database-specific, add to the appropriate database section

### 4. Validate

```bash
./scripts/validate.sh
```

### 5. Test Deployment

```bash
./scripts/deploy.sh <platform> --dry-run
```

### 6. Verify Cross-Reference Integrity

Ensure:
- Every rule ID in `rules/` appears in the corresponding `mappings/` file
- Every test ID in `mappings/test-to-siem.json` has matching rule IDs for all 11 platforms
- Every MITRE technique reference exists in `mappings/mitre-to-siem.json`
- Every compliance reference is present in the appropriate regulatory mapping file

---

## Design Principles

1. **Semantic Equivalence**: Every detection concept must be expressible on every platform, even if the implementation differs.
2. **Native Expression**: Rules use each platform's native query language (KQL, SPL, AQL, EQL, etc.) — not a lowest-common-denominator abstraction.
3. **Cross-Reference Integrity**: Every rule links back to its source test ID, MITRE technique(s), and regulatory controls.
4. **Severity Consistency**: The same threat has the same severity level across all platforms, adjusted for platform-specific naming conventions.
5. **Traceability**: Any alert can be traced from SIEM rule → test ID → compliance framework → MITRE technique and back.
6. **Coverage Completeness**: When adding a rule for one platform, it must be added for all 11 platforms to maintain cross-mapping integrity.