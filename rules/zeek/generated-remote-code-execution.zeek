# Zeek SIEM Alert Rules — generated-remote-code-execution
# Auto-generated: 2026-09-18T04:05:05.753586Z
# Load in local.zeek: @load ./generated-remote-code-execution

signature ZK-REMOTE-CODE-EXECUTION-003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-72530).*/ regex
	event "CVE-2026-72530 — Server Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2025\-62593).*/ regex
	event "CVE-2025-62593 — Ray Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-63077).*/ regex
	event "CVE-2026-63077 — TeamCity Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-9198).*/ regex
	event "CVE-2026-9198 — Langflow Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-72530).*/ regex
	event "CVE-2026-72530 — Server Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2025\-62593).*/ regex
	event "CVE-2025-62593 — Ray Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-9586).*/ regex
	event "CVE-2026-9586 — Switchvox Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-83549).*/ regex
	event "CVE-2026-83549 — SMA1000 Appliances Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-85046).*/ regex
	event "CVE-2026-85046 — Chromium V8 Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-83549).*/ regex
	event "CVE-2026-83549 — SMA1000 Appliances Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-83549).*/ regex
	event "CVE-2026-83549 — SMA1000 Appliances Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-009 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-85046).*/ regex
	event "CVE-2026-85046 — Chromium V8 Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-83549).*/ regex
	event "CVE-2026-83549 — SMA1000 Appliances Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-85046).*/ regex
	event "CVE-2026-85046 — Chromium V8 Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((powershell|cmd\.exe|bash|python|perl|ruby)).*/ regex
	event "CVE-2026-85706 — Community Edition and Enterprise Edition Exploitation"
}

signature ZK-REMOTE-CODE-EXECUTION-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|password|passwd)).*/ regex
	event "CVE-2026-86218 — N-central Exploitation"
}
