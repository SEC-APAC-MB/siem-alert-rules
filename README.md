# 🚨 SIEM Alert Rules — 29,307 Detection Rules

**Production-ready SIEM alert rules mapped from security test checks, live threat intel, and pentest techniques.**

> **Verified count**: 29,307 rules across 11 platforms as of 2026-10-12. Daily generation engine
> adds rules from CISA KEV, NVD CVE, and MITRE ATT&CK. Target: 2,500+ per platform.
> Weekly cleanup: stale CVEs (>12 months) removed, revoked MITRE techniques flagged, XML validation enforced.

Covers OWASP WSTG, API Security, Mobile Security, AI/LLM Security, MITRE ATT&CK, 8 compliance frameworks, and database security across 11 SIEM/cloud platforms, with full regulatory cross-mapping.

## Platforms

| Platform | Rules | Format | Directory |
|----------|-------|--------|------------|
| Elastic Security (Kibana) | 5,496 | KQL/EQL + Rule API JSON | `rules/elastic/` |
| Splunk Enterprise | 4,947 | SPL + correlation searches | `rules/splunk/` |
| FortiSIEM | 1,109 | Pattern-based XML | `rules/fortisiem/` |
| IBM QRadar | 886 | AQL + custom rules | `rules/qradar/` |
| Microsoft Sentinel | 902 | KQL analytics rules | `rules/sentinel/` |
| Wazuh | 10,152 | Custom rules (XML) | `rules/wazuh/` |
| Zeek (Bro) | 403 | Zeek script signatures | `rules/zeek/` |
| Suricata | 2,319 | Emerging threats + custom | `rules/suricata/` |
| Oracle Cloud Infrastructure | 1,292 | OCI Alarm + Event rules | `rules/oracle/` |
| Microsoft Azure | 978 | Azure Monitor + Policy | `rules/azure/` |
| AWS | 823 | CloudWatch + EventBridge + GuardDuty | `rules/aws/` |

## Regulatory Cross-Mapping

Every SIEM rule is cross-mapped to regulatory frameworks:

| Framework | Controls Mapped | Directory |
|-----------|----------------|------------|
| PCI-DSS v4.0 | 406 test IDs → 812+ rule mappings | `mappings/pci-dss-mappings.json` |
| GDPR | 266 test IDs → 532+ rule mappings | `mappings/gdpr-mappings.json` |
| HIPAA | 288 test IDs → 576+ rule mappings | `mappings/hipaa-mappings.json` |
| NIST 800-53 Rev 5 | 367 test IDs → 734+ rule mappings | `mappings/nist-mappings.json` |
| EU NIS2 Directive | 367 test IDs → 734+ rule mappings | `mappings/nis2-mappings.json` |
| EU DORA | 241 test IDs → 482+ rule mappings | `mappings/dora-mappings.json` |
| EU Data Act | 268 test IDs → 536+ rule mappings | `mappings/data-act-mappings.json` |
| EU AI Act | 311 test IDs → 622+ rule mappings | `mappings/ai-act-mappings.json` |
| **All-to-All Cross Map** | 7,483 test IDs × 11 platforms | `mappings/regulatory-cross-map.json` |

### Cross-Mapping Format

Each mapping links: `Test ID → SIEM Rule IDs (per platform) → Regulatory Controls → MITRE ATT&CK Techniques`

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
    "wazuh": "WZ-AI-PI-001",
    "zeek": "ZK-AI-PI-001",
    "suricata": "SUR-AI-PI-001",
    "oracle": "OCI-AI-PI-001",
    "azure": "AZ-AI-PI-001",
    "aws": "AWS-AI-PI-001"
  },
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
  "severity": "critical",
  "databases": ["postgresql", "mongodb", "redis", "neo4j"]
}
```

## Coverage by Category

| Category | Tests Mapped | SIEM Rules |
|----------|-------------|------------|
| OWASP WSTG (10 catalogs) | 2,084 | 4,168 |
| API Security 2023 | 327 | 654 |
| Mobile Security (MASVS) | 239 | 478 |
| **AI/LLM Security** | **1,691** | **3,382** |
| MITRE ATT&CK Enterprise | 276 | 552 |
| Lateral Movement Chains | 161 | 322 |
| PCI-DSS v4.0 | 406 | 812 |
| GDPR | 266 | 532 |
| HIPAA | 288 | 576 |
| NIST 800-53 Rev 5 | 367 | 734 |
| NIS2 Directive | 367 | 734 |
| DORA | 241 | 482 |
| Data Act | 268 | 536 |
| AI Act | 311 | 622 |
| + Platform-specific variations | — | ~5,000+ |
| **Grand Total** | — | **~20,000+** |
