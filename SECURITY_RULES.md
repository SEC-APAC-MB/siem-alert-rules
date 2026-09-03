# Security Rules — SIEM Alert Rules Repository

**Repository:** siem-alert-rules
**Version:** 1.0
**Date:** 2026-08-25
**Enforcement:** Same as R1-R26 redlines. Violation = STOP → PRESERVE → NOTIFY → WAIT.

---

## Category 1: Data Integrity & Trust (Rules 1-10)

1. **SIEM-001** — CRITICAL: All cached threat intel must be SHA-256 verified against pinned hashes before use. No integrity check = no trust.
2. **SIEM-002** — CRITICAL: CISA KEV, NVD, and MITRE ATT&CK data must verify HTTPS certificate pinning on fetch. No downgrade to HTTP.
3. **SIEM-003** — CRITICAL: Zeek signature generation must sanitize all rule fields before interpolation. No f-string injection of unsanitized threat intel data.
4. **SIEM-004** — CRITICAL: Suricata rule generation must escape quotes, semicolons, and special characters in content fields. No raw tag interpolation.
5. **SIEM-005** — HIGH: Rule name fields must be validated (alphanumeric + hyphens only, max 80 chars) before insertion into any rule format.
6. **SIEM-006** — HIGH: Query/pattern fields must be regex-escaped before insertion into Zeek, Suricata, or Elastic rule formats.
7. **SIEM-007** — HIGH: Cached threat intel files must include a `.sha256` sidecar file; generation scripts must verify the hash before loading.
8. **SIEM-008** — HIGH: Threat intel fetch must use retry with exponential backoff and validate HTTP status codes. Silent failure = stale data = false negatives.
9. **SIEM-009** — MEDIUM: Generated rule files must include a `generated_at` timestamp and `source_hash` metadata for traceability.
10. **SIEM-010** — MEDIUM: Daily generation scripts must fail closed — if threat intel is stale (>24h old) or hash verification fails, abort and alert, never generate from untrusted data.

## Category 2: Repository Hygiene (Rules 11-20)

11. **SIEM-011** — CRITICAL: `.gitignore` must exclude `cache/`, `threat_intel/`, `logs/`, `generated/`, `*.pyc`, `__pycache__/`, `.env`, and `*.json.bak`.
12. **SIEM-012** — HIGH: No secrets, API keys, tokens, or credentials in source code. Use environment variables or `.env` (excluded from git).
13. **SIEM-013** — HIGH: No binary data or large JSON files (>1MB) in git. Cache and threat intel data belong in `.gitignore`.
14. **SIEM-014** — MEDIUM: Python scripts must use `requirements.txt` with pinned versions. No unpinned dependencies.
15. **SIEM-015** — MEDIUM: All scripts must have `if __name__ == "__main__"` guard. No top-level execution on import.
16. **SIEM-016** — MEDIUM: Generated rule files must never be committed to git. Only templates and generators are versioned.
17. **SIEM-017** — LOW: Audit log files must be append-only and stored outside the repository.
18. **SIEM-018** — LOW: Git hooks should validate YAML/JSON syntax before allowing commits.
19. **SIEM-019** — LOW: A `CONTRIBUTING.md` must specify the security review process for new rules.
20. **SIEM-020** — MEDIUM: `.env.example` must be provided with required variable names but no actual values.

## Category 3: Rule Generation Security (Rules 21-30)

21. **SIEM-021** — CRITICAL: `generate_all.py` and `generate_daily.py` must validate all input data against a schema before rule generation.
22. **SIEM-022** — HIGH: Elastic rule generation must escape all Lucene query special characters (`+`, `-`, `&&`, `||`, `!`, `(`, `)`, `{`, `}`, `[`, `]`, `^`, `"`, `~`, `*`, `?`, `:`, `\`).
23. **SIEM-023** — HIGH: Splunk rule generation must escape all SPL special characters before insertion into search queries.
24. **SIEM-024** — HIGH: QRadar rule generation must validate AQL syntax. No raw string interpolation of user-controlled data.
25. **SIEM-025** — HIGH: Wazuh rule generation must validate XML entity escaping. No unescaped `&`, `<`, `>` in rule content.
26. **SIEM-026** — MEDIUM: All generated rules must include a rule ID that is deterministic (hash of rule name + severity + category).
27. **SIEM-027** — MEDIUM: Rule severity must be validated against a fixed enum (CRITICAL, HIGH, MEDIUM, LOW, INFO). No arbitrary severity strings.
28. **SIEM-028** — MEDIUM: MITRE ATT&CK references in rules must be validated against the official MITRE taxonomy. No freeform ATT&CK tags.
29. **SIEM-029** — LOW: Generated rules must pass syntax validation (`splunk-wmt`, `elastic-lint`, or equivalent) before deployment.
30. **SIEM-030** — LOW: A dry-run mode must be available that generates rules without writing to disk, for CI testing.

## Category 4: Threat Intel Pipeline (Rules 31-40)

31. **SIEM-031** — CRITICAL: `threat_intel_ingest.py` must verify SHA-256 hashes of all downloaded data against published checksums.
32. **SIEM-032** — HIGH: Threat intel fetch must use `requests.get(url, timeout=30, verify=True)`. No `verify=False`.
33. **SIEM-033** — HIGH: If hash verification fails, the script must abort and log an alert. Never fall back to stale data silently.
34. **SIEM-034** — HIGH: CISA KEV data must be fetched from the official API endpoint only. No third-party mirrors.
35. **SIEM-035** — MEDIUM: Threat intel cache must have a TTL. Data older than 24 hours must be re-fetched before use.
36. **SIEM-036** — MEDIUM: The `cache/` directory must have restricted file permissions (0600). No world-readable cache files.
37. **SIEM-037** — MEDIUM: Network fetches must have configurable timeouts (default: connect 10s, read 30s).
38. **SIEM-038** — LOW: A `--offline` mode must be available that uses only cached data (with warning if stale).
39. **SIEM-039** — LOW: Threat intel ingestion must log the source URL, hash, and record count for audit.
40. **SIEM-040** — MEDIUM: Rate limiting must be applied to external API calls (max 1 request/second, configurable).

## Category 5: Rule Format Security (Rules 41-50)

41. **SIEM-041** — HIGH: Elastic rules must validate JSON schema before writing. No malformed JSON deployment.
42. **SIEM-042** — HIGH: Splunk rules must validate that all search queries are properly quoted. No unquoted field lookups.
43. **SIEM-043** — HIGH: Sentinel rules must validate KQL syntax. No raw interpolation of unsanitized data.
44. **SIEM-044** — HIGH: FortiSIEM rules must validate the XML/filter syntax. No unescaped special characters.
45. **SIEM-045** — MEDIUM: Azure Sentinel rules must use `yaml.safe_load()` for all YAML parsing. No `yaml.load()`.
46. **SIEM-046** — MEDIUM: Wazuh rules must escape all XML entities (`&`, `<`, `>`, `"`, `'`) in generated content.
47. **SIEM-047** — MEDIUM: Suricata rules must validate `sid` and `rev` fields are integers. No string interpolation.
48. **SIEM-048** — LOW: Zeek signatures must be validated against Zeek syntax before writing to output files.
49. **SIEM-049** — LOW: All rule formats must include a `references` field with CVE or MITRE IDs for traceability.
50. **SIEM-050** — MEDIUM: Oracle Cloud guard rules must validate JSON path syntax. No injection via JSON path.

## Category 6: Deployment Security (Rules 51-60)

51. **SIEM-051** — HIGH: Generated rules must be deployed via CI/CD pipeline, not manual copy. No ad-hoc rule deployment.
52. **SIEM-052** — HIGH: Rule deployment must require approval (CODEOWNER review). No auto-deploy without review.
53. **SIEM-053** — MEDIUM: Rule deployment scripts must have `--dry-run` mode that validates without pushing.
54. **SIEM-054** — MEDIUM: Production SIEM credentials must not exist in the repository. Use CI/CD secrets or vault.
55. **SIEM-055** — MEDIUM: Rule deployment must be idempotent — re-running should not duplicate rules.
56. **SIEM-056** — LOW: Deployment scripts must log all actions with timestamps and rule IDs.
57. **SIEM-057** — LOW: Rollback capability must exist for all rule deployments. No deployment without rollback plan.
58. **SIEM-058** — LOW: Rule deployment must validate target SIEM connectivity before pushing rules.
59. **SIEM-059** — MEDIUM: Deployment must handle partial failures gracefully. If 1 of N rules fails, deploy the rest and alert.
60. **SIEM-060** — LOW: A deployment audit log must be maintained for compliance.

## Category 7: Access Control & Secrets (Rules 61-70)

61. **SIEM-061** — CRITICAL: SIEM API keys must be stored in environment variables or secrets manager, never in config files.
62. **SIEM-062** — HIGH: `.env` files must be excluded from git (`.gitignore`).
63. **SIEM-063** — HIGH: API keys must have minimum required permissions (read-only for rule deployment, no admin access).
64. **SIEM-064** — HIGH: API keys must be rotated at least every 90 days. Scripts must warn if keys are older than 90 days.
65. **SIEM-065** — MEDIUM: Scripts must not log API keys, tokens, or credentials. Redact before logging.
66. **SIEM-066** — MEDIUM: Error messages must not include stack traces in production. Log to file, show generic error to user.
67. **SIEM-067** — LOW: A `--verbose` flag must control log detail level. Default is INFO, not DEBUG.
68. **SIEM-068** — LOW: Generated rule files must have 0644 permissions. No 0777 or world-writable rule files.
69. **SIEM-069** — MEDIUM: Script configuration files must have 0600 permissions. No world-readable configs with connection details.
70. **SIEM-070** — LOW: Secrets must never appear in git diff output. Use `git diff --check` in CI.

## Category 8: Logging & Monitoring (Rules 71-80)

71. **SIEM-071** — HIGH: All rule generation runs must be logged with: timestamp, source data hash, rules generated, errors.
72. **SIEM-072** — HIGH: Failed rule generation must trigger an alert (not just log and continue silently).
73. **SIEM-073** — MEDIUM: Log files must be rotated daily and retained for 90 days minimum.
74. **SIEM-074** — MEDIUM: Log files must not contain PII, credentials, or raw threat intel data.
75. **SIEM-075** — MEDIUM: The `logs/` directory must be excluded from git (`.gitignore`).
76. **SIEM-076** — LOW: Each rule generation run must produce a summary report with: rules generated, rules updated, rules deprecated.
77. **SIEM-077** — LOW: The generation log must include timing data (fetch time, parse time, generate time, total time).
78. **SIEM-078** — LOW: Anomalies (e.g., 0 rules generated, 10x spike in rules) must be flagged for manual review.
79. **SIEM-079** — MEDIUM: Audit log must be append-only. No deletion or modification of past entries.
80. **SIEM-080** — LOW: Log format must be structured JSON for machine parsing.

## Category 9: Supply Chain & Dependencies (Rules 81-90)

81. **SIEM-081** — HIGH: `requirements.txt` must pin all dependency versions (e.g., `requests==2.31.0`, not `requests>=2.28`).
82. **SIEM-082** — HIGH: A `pip-audit` or `safety check` must pass in CI before merge.
83. **SIEM-083** — MEDIUM: Python version must be pinned in CI (e.g., `python-version: '3.11'`).
84. **SIEM-084** — MEDIUM: No `--index-url` pointing to unofficial PyPI mirrors. Use official `pypi.org` only.
85. **SIEM-085** — MEDIUM: A `hash` mode requirements file (`requirements.hash`) must be used for production deployment.
86. **SIEM-086** — LOW: Dependency updates must be reviewed manually. No Dependabot auto-merge without review.
87. **SIEM-087** — LOW: A Software Bill of Materials (SBOM) must be generated for each release.
88. **SIEM-088** — LOW: New dependencies must be approved via security review before adding to `requirements.txt`.
89. **SIEM-089** — MEDIUM: Scripts must not use `pip install` at runtime. All dependencies must be pre-installed.
90. **SIEM-090** — LOW: A `.python-version` file must be committed for reproducibility.

## Category 10: Error Handling & Resilience (Rules 91-100)

91. **SIEM-091** — CRITICAL: If threat intel hash verification fails, generation must abort. No partial or stale rule generation.
92. **SIEM-092** — HIGH: Network errors during threat intel fetch must be retried (3 attempts, exponential backoff) before failing.
93. **SIEM-093** — HIGH: If a rule format generator fails, other format generators must continue. Report failure, don't abort all.
94. **SIEM-094** — HIGH: File I/O errors must be caught and logged. No silent `except: pass` blocks.
95. **SIEM-095** — MEDIUM: JSON/YAML parse errors in threat intel must be caught and reported with the specific file and line.
96. **SIEM-096** — MEDIUM: Scripts must validate output file permissions before writing. Fail if files are world-writable.
97. **SIEM-097** — MEDIUM: A `--validate-only` mode must exist that checks all inputs without generating rules.
98. **SIEM-098** — LOW: Scripts must handle keyboard interrupts gracefully (SIGINT). Clean up temp files.
99. **SIEM-099** — LOW: Temp files must use `tempfile.mkdtemp()` or `tempfile.NamedTemporaryFile(delete=True)`. No predictable paths.
100. **SIEM-100** — MEDIUM: Generation scripts must exit with non-zero status on any error. No silent failures (exit 0 on error).

---

*Generated: 2026-08-25 | SIEM Alert Rules Security Rules v1.0*
*Audit findings: 4 CRITICAL, 10+ HIGH, 12+ MEDIUM, 4+ LOW*