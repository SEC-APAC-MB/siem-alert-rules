# Zeek SIEM Alert Rules — generated-general
# Auto-generated: 2026-09-21T04:05:05.389751Z
# Load in local.zeek: @load ./generated-general

signature ZK-GENERAL-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-73570).*/ regex
	event "CVE-2026-73570 — Zimbra Collaboration Suite (ZCS) Exploitation"
}

signature ZK-GENERAL-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-72529).*/ regex
	event "CVE-2026-72529 — Server Exploitation"
}

signature ZK-GENERAL-008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-55040).*/ regex
	event "CVE-2026-55040 — SharePoint Exploitation"
}

signature ZK-GENERAL-009 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-65400).*/ regex
	event "CVE-2026-65400 — macOS Exploitation"
}

signature ZK-GENERAL-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-8037).*/ regex
	event "CVE-2026-8037 — LoadMaster Exploitation"
}

signature ZK-GENERAL-016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-18556).*/ regex
	event "CVE-2026-18556 — N-central Exploitation"
}

signature ZK-GENERAL-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-18577).*/ regex
	event "CVE-2026-18577 — N-central Exploitation"
}

signature ZK-GENERAL-003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-66384).*/ regex
	event "CVE-2026-66384 — Artifactory Exploitation"
}

signature ZK-GENERAL-010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-60004).*/ regex
	event "CVE-2026-60004 — Gitea Exploitation"
}

signature ZK-GENERAL-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-73570).*/ regex
	event "CVE-2026-73570 — Zimbra Collaboration Suite (ZCS) Exploitation"
}

signature ZK-GENERAL-018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-55040).*/ regex
	event "CVE-2026-55040 — SharePoint Exploitation"
}

signature ZK-GENERAL-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-66384).*/ regex
	event "CVE-2026-66384 — Artifactory Exploitation"
}

signature ZK-GENERAL-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-55040).*/ regex
	event "CVE-2026-55040 — SharePoint Exploitation"
}

signature ZK-GENERAL-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-8452).*/ regex
	event "CVE-2026-8452 — NetScaler ADC and NetScaler Gateway Exploitation"
}

signature ZK-GENERAL-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-66384).*/ regex
	event "CVE-2026-66384 — Artifactory Exploitation"
}

signature ZK-GENERAL-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-59822).*/ regex
	event "CVE-2026-59822 — LiteLLM Exploitation"
}

signature ZK-GENERAL-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|password|passwd)).*/ regex
	event "CVE-2026-84869 — ScreenConnect Exploitation"
}

signature ZK-GENERAL-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|password|passwd)).*/ regex
	event "CVE-2026-19490 — NetScaler Exploitation"
}
