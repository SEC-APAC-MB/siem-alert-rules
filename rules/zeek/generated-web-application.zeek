# Zeek SIEM Alert Rules — generated-web-application
# Auto-generated: 2026-10-06T06:00:26.160334Z
# Load in local.zeek: @load ./generated-web-application

signature ZK-WEB-APPLICATION-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-34486).*/ regex
	event "CVE-2026-34486 — Tomcat Exploitation"
}
