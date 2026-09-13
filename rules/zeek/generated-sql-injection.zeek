# Zeek SIEM Alert Rules — generated-sql-injection
# Auto-generated: 2026-09-13T22:00:56.751112Z
# Load in local.zeek: @load ./generated-sql-injection

signature ZK-SQL-INJECTION-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-72898).*/ regex
	event "CVE-2026-72898 — Metabase Exploitation"
}
