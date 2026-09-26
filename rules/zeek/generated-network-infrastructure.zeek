# Zeek SIEM Alert Rules — generated-network-infrastructure
# Auto-generated: 2026-09-26T04:05:06.158535Z
# Load in local.zeek: @load ./generated-network-infrastructure

signature ZK-NETWORK-INFRASTRUCTURE-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-20349).*/ regex
	event "CVE-2026-20349 — Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD)  Exploitation"
}

signature ZK-NETWORK-INFRASTRUCTURE-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-20316).*/ regex
	event "CVE-2026-20316 — Secure Firewall Management Center (FMC) Exploitation"
}

signature ZK-NETWORK-INFRASTRUCTURE-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-20079).*/ regex
	event "CVE-2026-20079 — Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management Exploitation"
}

signature ZK-NETWORK-INFRASTRUCTURE-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-20079).*/ regex
	event "CVE-2026-20079 — Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management Exploitation"
}

signature ZK-NETWORK-INFRASTRUCTURE-010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-20079).*/ regex
	event "CVE-2026-20079 — Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management Exploitation"
}
