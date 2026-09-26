# Zeek SIEM Alert Rules — generated-sql-injection
# Auto-generated: 2026-09-26T04:05:06.159938Z
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

signature ZK-SQL-INJECTION-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((union|select|script|alert|onload|onerror|\.\./|\.\.\\)).*/ regex
	event "CVE-2026-76461 — Secure Email Gateway Exploitation"
}

signature ZK-SQL-INJECTION-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|password|passwd)).*/ regex
	event "CVE-2026-76461 — Secure Email Gateway Exploitation"
}
