# Zeek SIEM Alert Rules — generated-sql-injection
# Auto-generated: 2026-09-19T04:05:04.248143Z
# Load in local.zeek: @load ./generated-sql-injection

signature ZK-SQL-INJECTION-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-72898).*/ regex
	event "CVE-2026-72898 — Metabase Exploitation"
}

signature ZK-SQL-INJECTION-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|password|passwd)).*/ regex
	event "CVE-2026-76461 — Secure Email Gateway Exploitation"
}

signature ZK-SQL-INJECTION-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin|root)).*/ regex
	event "CVE-2026-76461 — Secure Email Gateway Exploitation"
}
