# Zeek SIEM Alert Rules — generated-endpoint
# Auto-generated: 2026-09-14T04:05:03.479196Z
# Load in local.zeek: @load ./generated-endpoint

signature ZK-ENDPOINT-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-33824).*/ regex
	event "CVE-2026-33824 — Internet Key Exchange (IKE) Service Extensions Exploitation"
}

signature ZK-ENDPOINT-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-68820).*/ regex
	event "CVE-2026-68820 — Windows Ancillary Function Driver for WinSock  Exploitation"
}

signature ZK-ENDPOINT-016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-33824).*/ regex
	event "CVE-2026-33824 — Internet Key Exchange (IKE) Service Extensions Exploitation"
}

signature ZK-ENDPOINT-018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-33824).*/ regex
	event "CVE-2026-33824 — Internet Key Exchange (IKE) Service Extensions Exploitation"
}

signature ZK-ENDPOINT-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-81963).*/ regex
	event "CVE-2026-81963 — Windows Exploitation"
}

signature ZK-ENDPOINT-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-85880).*/ regex
	event "CVE-2026-85880 — Windows Exploitation"
}

signature ZK-ENDPOINT-008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-85880).*/ regex
	event "CVE-2026-85880 — Windows Exploitation"
}

signature ZK-ENDPOINT-010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-85880).*/ regex
	event "CVE-2026-85880 — Windows Exploitation"
}

signature ZK-ENDPOINT-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-85880).*/ regex
	event "CVE-2026-85880 — Windows Exploitation"
}
