# Zeek SIEM Alert Rules — generated-web-application
# Auto-generated: 2026-09-23T04:05:05.329894Z
# Load in local.zeek: @load ./generated-web-application

signature ZK-WEB-APPLICATION-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-34486).*/ regex
	event "CVE-2026-34486 — Tomcat Exploitation"
}
