# Zeek SIEM Alert Rules — generated-privilege-escalation
# Auto-generated: 2026-09-14T04:05:03.480435Z
# Load in local.zeek: @load ./generated-privilege-escalation

signature ZK-PRIVILEGE-ESCALATION-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-53362).*/ regex
	event "CVE-2026-53362 — Kernel Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-3246).*/ regex
	event "CVE-2015-3246 — Libuser Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-5287).*/ regex
	event "CVE-2015-5287 — Automatic Bug Reporting Tool Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-53362).*/ regex
	event "CVE-2026-53362 — Kernel Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-3246).*/ regex
	event "CVE-2015-3246 — Libuser Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-5287).*/ regex
	event "CVE-2015-5287 — Automatic Bug Reporting Tool Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-53362).*/ regex
	event "CVE-2026-53362 — Kernel Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-3246).*/ regex
	event "CVE-2015-3246 — Libuser Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-5287).*/ regex
	event "CVE-2015-5287 — Automatic Bug Reporting Tool Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-53362).*/ regex
	event "CVE-2026-53362 — Kernel Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-5287).*/ regex
	event "CVE-2015-5287 — Automatic Bug Reporting Tool Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-3246).*/ regex
	event "CVE-2015-3246 — Libuser Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2015\-5287).*/ regex
	event "CVE-2015-5287 — Automatic Bug Reporting Tool Exploitation"
}

signature ZK-PRIVILEGE-ESCALATION-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-86060).*/ regex
	event "CVE-2026-86060 — RouterOS Exploitation"
}
