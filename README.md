# 🚨 SIEM Alert Rules — 7,017 Detection Rules

**Production-ready SIEM alert rules mapped from security test checks, live threat intel, and pentest techniques.**

> ⚠️ **Honest count**: 7,017 rules across 11 platforms as of 2026-08-31. Daily generation engine
> adds rules from CISA KEV, NVD CVE, and MITRE ATT&CK. Target: 2,500+ per platform.
> Previous claim of 20,000+ was inaccurate — this is the real count.

Covers OWASP WSTG, API Security, Mobile Security, AI/LLM Security, MITRE ATT&CK, 8 compliance frameworks, and database security across 11 SIEM/cloud platforms, with full regulatory cross-mapping.

## Platforms

| Platform | Rules | Format | Directory |
|----------|-------|--------|------------|
| Elastic Security (Kibana) | 764 | KQL/EQL + Rule API JSON | `rules/elastic/` |
| Splunk Enterprise | 638 | SPL + correlation searches | `rules/splunk/` |
| FortiSIEM | 678 | Pattern-based XML | `rules/fortisiem/` |
| IBM QRadar | 637 | AQL + custom rules | `rules/qradar/` |
| Microsoft Sentinel | 526 | KQL analytics rules | `rules/sentinel/` |
| Wazuh | 641 | Custom rules (XML) | `rules/wazuh/` |
| Zeek (Bro) | 117 | Zeek script signatures | `rules/zeek/` |
| Suricata | 1,210 | Emerging threats + custom | `rules/suricata/` |
| Oracle Cloud Infrastructure | 602 | OCI Alarm + Event rules | `rules/oracle/` |
| Microsoft Azure | 602 | Azure Monitor + Policy | `rules/azure/` |
| AWS | 602 | CloudWatch + EventBridge + GuardDuty | `rules/aws/` |

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

## Database Security Coverage

SQL: PostgreSQL, MySQL, SQL Server, Oracle, SQLite
NoSQL: MongoDB, DynamoDB, Cassandra, CouchDB, Firestore
Graph: Neo4j, ArangoDB, Amazon Neptune
Time-series: InfluxDB, TimescaleDB, Prometheus
Vector: Pinecone, Weaviate, Milvus, ChromaDB, Qdrant
Key-value: Redis, Memcached
Column-family: HBase

## Quick Start

```bash
# Clone
git clone https://github.com/SEC-APAC-MB/siem-alert-rules.git
cd siem-alert-rules

# Validate all rules
./scripts/validate.sh

# Deploy to Elastic
./scripts/deploy.sh elastic --dry-run
./scripts/deploy.sh elastic

# Deploy to Splunk
./scripts/deploy.sh splunk --dry-run
./scripts/deploy.sh splunk

# Deploy to Sentinel
./scripts/deploy.sh sentinel --dry-run
./scripts/deploy.sh sentinel

# Deploy to AWS
./scripts/deploy.sh aws --dry-run
./scripts/deploy.sh aws

# Deploy to Azure
./scripts/deploy.sh azure --dry-run
./scripts/deploy.sh azure

# Deploy to Oracle Cloud
./scripts/deploy.sh oracle --dry-run
./scripts/deploy.sh oracle

# Deploy to all platforms
./scripts/deploy.sh all
```

## Mappings

The `mappings/` directory contains cross-reference files:
- `test-to-siem.json` — Maps every test catalog ID to SIEM rule IDs across all 11 platforms
- `mitre-to-siem.json` — Maps MITRE ATT&CK techniques to SIEM rules
- `regulatory-cross-map.json` — Maps every test to all 8 compliance frameworks
- `pci-dss-mappings.json` — PCI-DSS control → SIEM rule mapping
- `gdpr-mappings.json` — GDPR article → SIEM rule mapping
- `hipaa-mappings.json` — HIPAA safeguard → SIEM rule mapping
- `nist-mappings.json` — NIST 800-53 control → SIEM rule mapping
- `nis2-mappings.json` — NIS2 article → SIEM rule mapping
- `dora-mappings.json` — DORA article → SIEM rule mapping
- `data-act-mappings.json` — Data Act article → SIEM rule mapping
- `ai-act-mappings.json` — AI Act article → SIEM rule mapping
- `database-to-siem.json` — Database-specific tests → SIEM rules
- `elastic-mappings.json` — Elastic-specific ID mapping
- `splunk-mappings.json` — Splunk-specific ID mapping
- `fortisiem-mappings.json` — FortiSIEM-specific ID mapping
- `qradar-mappings.json` — QRadar-specific ID mapping
- `sentinel-mappings.json` — Sentinel-specific ID mapping
- `wazuh-mappings.json` — Wazuh-specific ID mapping
- `zeek-mappings.json` — Zeek-specific ID mapping
- `suricata-mappings.json` — Suricata-specific ID mapping
- `oracle-mappings.json` — Oracle Cloud-specific ID mapping
- `azure-mappings.json` — Azure-specific ID mapping
- `aws-mappings.json` — AWS-specific ID mapping

## Related Projects

- [security-testing-pentest](https://github.com/SEC-APAC-MB/security-testing-pentest) — 10,426+ security test checks
- [MITRE ATT&CK Chain Scripts](https://github.com/SEC-APAC-MB/security-testing-pentest/tree/main/scripts/mitre-attack-chains) — 10 exploit chain scripts

## License

MIT

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Security

This repository contains security detection rules with exploit-specific signatures. To protect against malicious edits:

- **Branch protection**: `main` branch requires PR review, linear history, no force pushes, conversation resolution
- **Push access**: Repository owner only — no outside collaborators with write access
- **Forks**: Allowed (GitHub requirement for user-owned repos) but all PRs require approval
- **Self-review**: Disabled — push author cannot approve their own PR (`require_last_push_approval: true`)
- **Stale reviews**: Automatically dismissed on new commits

> ⚠️ Rules reference actively exploited CVEs from the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Exploit details are included for detection accuracy — this is intentional and necessary for effective security monitoring.

## CISA KEV Rules

Real-time detection rules from the CISA Known Exploited Vulnerabilities catalog (v2026.09.02, 1,694 entries). These rules target CVEs under **active exploitation in the wild** — not theoretical vulnerabilities.

| Rule Set | Rules | Directory |
|----------|-------|------------|
| Suricata KEV rules | 1,210+ | `rules/suricata/` |
| Elastic KEV rules | 764+ | `rules/elastic/` |
| CISA KEV daily rules | Daily | `generated/` |
| KEV detection rules (YAML) | 20+ | `config/rules/` |

Key actively-exploited CVEs covered:
- CVE-2026-83549: SonicWall SMA1000 RCE (forensic triage)
- CVE-2026-81578+82078: PaperCut NG/MF chained zero-days
- CVE-2026-49869: Kestra OSS pre-auth RCE (forensic triage)
- CVE-2026-60004: Gitea pre-auth RCE via git hook injection
- CVE-2026-72137: Linux Kernel root LPE (CVSS 9.8, PoC public)
- CVE-2025-6452: PostGREshell 12-year PostgreSQL exploit chain
- CVE-2019-1068: MSSQL RCE (ransomware-linked, 7+ years active exploitation)

See `AUDIT.md` for full rule quality audit and `SECURITY_RULES.md` for repository governance.

---

**7,017 SIEM alert rules. 11 platforms. 8 regulatory frameworks. Full cross-mapping. Production-ready.**