# Zeek SIEM Alert Rules — generated-privilege-escalation
# Auto-generated: 2026-09-18T04:05:05.753142Z
# Load in local.zeek: @load ./generated-privilege-escalation

signature ZK-PRIVILEGE-ESCALATION-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-53362).*/ regex
	event "CVE-2026-53362 — Kernel Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-53362).*/ regex
	event "CVE-2026-53362 — Kernel Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-53362).*/ regex
	event "CVE-2026-53362 — Kernel Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-53362).*/ regex
	event "CVE-2026-53362 — Kernel Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-86060).*/ regex
	event "CVE-2026-86060 — RouterOS Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((sudo|runas|setuid|chmod)).*/ regex
	event "CVE-2026-86060 — RouterOS Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((sudo|runas|setuid|chmod)).*/ regex
	event "CVE-2026-42016 — Artifactory Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((sudo|runas|setuid|chmod)).*/ regex
	event "CVE-2026-86060 — RouterOS Exploitation"
}
