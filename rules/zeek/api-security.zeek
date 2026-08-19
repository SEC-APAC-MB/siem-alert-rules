# =============================================================================
# Zeek Signatures — API Security
# Total rules: 32
# MITRE ATT&CK: T1190, T1078, T1548, T1567, T1040
# Compliance: PCI-DSS 6.5, GDPR 32, HIPAA 164.312, NIST SI-4, AC-4
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# API Authentication Abuse
# =============================================================================

signature ZK-APISEC-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/api\/v[0-9]+\/(login|auth|signin|authenticate|token)/ regex
	http-response /401 Unauthorized|403 Forbidden/ regex
	event "API-SEC-001: API authentication failure - invalid credentials"
}

signature ZK-APISEC-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /Authorization: Bearer (null|undefined|expired|invalid|test|admin|root|sk-test|pk-test)/ regex
	event "API-SEC-002: API request with invalid/expired/test bearer token"
}

signature ZK-APISEC-003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /Authorization: Bearer .*/ regex
	http-header /Authorization: Bearer .*/ regex
	event "API-SEC-003: API request with duplicated authorization headers"
}

signature ZK-APISEC-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /!(Authorization)/ regex
	http-response /401 Unauthorized/ regex
	event "API-SEC-004: API request without authentication - unauthorized access attempt"
}

# =============================================================================
# API Rate Limiting
# =============================================================================

signature ZK-APISEC-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(GET|POST|PUT|DELETE|PATCH) \/api\/v[0-9]+\/.*/ regex
	http-response /429 Too Many Requests/ regex
	event "API-SEC-005: API rate limit exceeded - potential abuse or DDoS"
}

signature ZK-APISEC-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(GET|POST|PUT|DELETE|PATCH) \/api\/v[0-9]+\/.*/ regex
	http-header /User-Agent: .*(python-requests|curl|wget|Go-http|node-fetch|axios|aiohttp|http\.rb)/ regex
	event "API-SEC-006: API automated access from script/bot user-agent"
}

# =============================================================================
# API Injection
# =============================================================================

signature ZK-APISEC-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/.*/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*\{.*"\$where".*:.*\$gt".*:.*\$ne".*:.*\$regex".*:.*\$expr".*:.*\}.*\}.*/ regex
	event "API-SEC-007: NoSQL injection in JSON API payload"
}

signature ZK-APISEC-008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/.*/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*\{.*"(password|secret|token|api_key|private_key)"\s*:\s*"\$gt".*/ regex
	event "API-SEC-008: NoSQL injection targeting authentication fields"
}

signature ZK-APISEC-009 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*\?.*(%27|%22|%3B|%2D%2D|%2F%2A|%2A%2F|UNION|SELECT|INSERT|UPDATE|DELETE|DROP).*/ regex
	event "API-SEC-009: SQL injection in API query parameter"
}

signature ZK-APISEC-010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/.*/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*\{.*"(role|isAdmin|permissions|privileges|account_type)"\s*:\s*"(admin|superuser|root|manager|premium)".*/ regex
	event "API-SEC-010: Mass assignment - role/privilege escalation via API"
}

# =============================================================================
# API IDOR
# =============================================================================

signature ZK-APISEC-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(users|accounts|orders|transactions|documents|records)\/\d+/ regex
	http-header /Authorization: Bearer .*/ regex
	event "API-SEC-011: API IDOR - sequential numeric ID resource access"
}

signature ZK-APISEC-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(PUT|PATCH|DELETE) \/api\/v[0-9]+\/(users|accounts|orders|transactions)\/\d+/ regex
	http-header /Authorization: Bearer .*/ regex
	http-response /200 OK|204 No Content/ regex
	event "API-SEC-012: API IDOR - modification of resource by numeric ID"
}

signature ZK-APISEC-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(users|accounts|orders|transactions)\/[a-f0-9]{8,}/ regex
	http-header /Authorization: Bearer .*/ regex
	http-response /200 OK/ regex
	event "API-SEC-013: API IDOR - resource access by predictable UUID"
}

# =============================================================================
# API Data Exposure
# =============================================================================

signature ZK-APISEC-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*"(password|secret|api_key|token|private_key|ssn|credit_card|bank_account|social_security)".*/ regex
	event "API-SEC-014: API response containing sensitive field - data exposure"
}

signature ZK-APISEC-015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(users|accounts|customers)\?(.*&)?(fields=|include=).*(password|token|secret|ssn|credit_card|bank_account)/ regex
	event "API-SEC-015: API field filtering to extract sensitive fields"
}

signature ZK-APISEC-016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	http-header /Content-Type: application\/json/ regex
	http-header /X-Total-Count: [0-9]{5,}/ regex
	event "API-SEC-016: API response with excessive total count - data enumeration"
}

# =============================================================================
# API CORS/Security Headers
# =============================================================================

signature ZK-APISEC-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /Origin: .*/ regex
	http-response /Access-Control-Allow-Origin: \*/ regex
	http-response /Access-Control-Allow-Credentials: true/ regex
	event "API-SEC-017: API CORS wildcard with credentials - security misconfiguration"
}

signature ZK-APISEC-018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	http-header /!(X-Content-Type-Options)/ regex
	http-header /!(X-Frame-Options)/ regex
	event "API-SEC-018: API response missing security headers"
}

# =============================================================================
# API Versioning/Deprecation
# =============================================================================

signature ZK-APISEC-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/(v0|v1-alpha|v1-beta|v1-rc|v1-test|internal|staging|dev)\/.*/ regex
	event "API-SEC-019: API access to internal/alpha/beta version"
}

signature ZK-APISEC-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /X-API-Version: (0|1-alpha|1-beta|deprecated)/ regex
	event "API-SEC-020: API deprecated version accessed"
}

# =============================================================================
# API GraphQL
# =============================================================================

signature ZK-APISEC-021 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|GET) \/graphql/ regex
	payload /.*__schema.*|.*__type.*|.*introspection.*/ regex
	event "API-SEC-021: GraphQL introspection query - schema exposure"
}

signature ZK-APISEC-022 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/graphql/ regex
	payload /.*\{.*\b(users|accounts|customers|orders|transactions|payments|documents)\b.*\{.*\b(password|token|secret|ssn|credit_card|api_key|private_key)\b.*/ regex
	event "API-SEC-022: GraphQL query requesting sensitive fields"
}

signature ZK-APISEC-023 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/graphql/ regex
	payload /.*\{.*\{.*\{.*\{.*\}.*/ regex
	event "API-SEC-023: GraphQL deeply nested query - potential DoS"
}

# =============================================================================
# API Token/JWT Abuse
# =============================================================================

signature ZK-APISEC-024 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0/ regex
	event "API-SEC-024: JWT none algorithm - algorithm confusion attack"
}

signature ZK-APISEC-025 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /Authorization: Bearer .*/ regex
	http-header /X-Forwarded-For: .*/ regex
	http-header /X-Real-IP: .*/ regex
	event "API-SEC-025: API request with both X-Forwarded-For and X-Real-IP - IP spoofing risk"
}

# =============================================================================
# API Webhook Abuse
# =============================================================================

signature ZK-APISEC-026 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/(webhooks?|hooks?|callbacks?|notifications?)/ regex
	payload /.*"(url|endpoint|target|callback)"\s*:\s*"(http|https):\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|169\.254\.169\.254|metadata\.google\.internal).*/ regex
	event "API-SEC-026: Webhook pointing to internal/private network - SSRF risk"
}

signature ZK-APISEC-027 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(webhooks?|hooks?|callbacks?|notifications?)/ regex
	payload /.*"(secret|signature|token|key)"\s*:\s*"[^"]*".*/ regex
	event "API-SEC-027: Webhook creation with explicit secret/key - potential secret leakage"
}

# =============================================================================
# API Batch/Bulk Abuse
# =============================================================================

signature ZK-APISEC-028 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH|DELETE) \/api\/v[0-9]+\/(batch|bulk|mass|export|import)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "API-SEC-028: API batch/bulk operation - potential data exfiltration"
}

signature ZK-APISEC-029 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(users|accounts|customers|records)\?(.*&)?(limit=|per_page=|page_size=|count=)(10000|100000|1000000|-1|all|unlimited)/ regex
	event "API-SEC-029: API request for excessive data - pagination bypass"
}

# =============================================================================
# API Error Information Disclosure
# =============================================================================

signature ZK-APISEC-030 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /500 Internal Server Error/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*(stack trace|Traceback|Exception|internal error|debug|stacktrace|at .*\.java:\d+|at .*\.py:\d+|at .*\.rb:\d+|in .*\.php.*line \d+).*/ regex
	event "API-SEC-030: API 500 error with stack trace disclosure"
}

signature ZK-APISEC-031 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /(400|401|403|404|405|409|422|500)/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*(ORA-\d{5}|SQLSTATE\[|MySQL Error|PostgreSQL query failed|Unclosed quotation|Microsoft OLE DB|connection string|jdbc:|mongodb:).*/ regex
	event "API-SEC-031: API error response disclosing database information"
}

signature ZK-APISEC-032 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(GET|POST|PUT|DELETE|PATCH) \/api\/v[0-9]+\/.*/ regex
	http-header /Authorization: Basic .*/ regex
	event "API-SEC-032: API authentication via Basic Auth over potentially insecure channel"
}