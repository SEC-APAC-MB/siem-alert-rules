# Zeek SIEM Alert Rules — generated-cloud-container
# Auto-generated: 2026-09-26T04:05:06.156107Z
# Load in local.zeek: @load ./generated-cloud-container

signature ZK-CLOUD-CONTAINER-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-59310).*/ regex
	event "CVE-2026-59310 — VMware vCenter Exploitation"
}

signature ZK-CLOUD-CONTAINER-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-59310).*/ regex
	event "CVE-2026-59310 — VMware vCenter Exploitation"
}

signature ZK-CLOUD-CONTAINER-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-59310).*/ regex
	event "CVE-2026-59310 — VMware vCenter Exploitation"
}
