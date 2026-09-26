# Zeek SIEM Alert Rules — generated-ssrf
# Auto-generated: 2026-09-26T04:05:06.160333Z
# Load in local.zeek: @load ./generated-ssrf

signature ZK-SSRF-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-64849).*/ regex
	event "CVE-2026-64849 — MLflow Exploitation"
}

signature ZK-SSRF-015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-64849).*/ regex
	event "CVE-2026-64849 — MLflow Exploitation"
}

signature ZK-SSRF-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-64849).*/ regex
	event "CVE-2026-64849 — MLflow Exploitation"
}

signature ZK-SSRF-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-83548).*/ regex
	event "CVE-2026-83548 — SMA1000 Appliances Exploitation"
}

signature ZK-SSRF-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-83548).*/ regex
	event "CVE-2026-83548 — SMA1000 Appliances Exploitation"
}

signature ZK-SSRF-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-83548).*/ regex
	event "CVE-2026-83548 — SMA1000 Appliances Exploitation"
}
