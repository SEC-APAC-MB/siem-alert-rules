# Zeek SIEM Alert Rules — generated-reconnaissance
# Auto-generated: 2026-10-12T06:00:32.459262Z
# Load in local.zeek: @load ./generated-reconnaissance

signature ZK-RECONNAISSANCE-097 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Active Directory Domain Enumeration"
}

signature ZK-RECONNAISSANCE-098 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Network Service Discovery (Nmap/Masscan)"
}

signature ZK-RECONNAISSANCE-099 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "DNS Zone Transfer Attempt"
}

signature ZK-RECONNAISSANCE-100 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Web Technology Fingerprinting"
}

signature ZK-RECONNAISSANCE-077 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Active Directory Domain Enumeration"
}

signature ZK-RECONNAISSANCE-078 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Network Service Discovery (Nmap/Masscan)"
}

signature ZK-RECONNAISSANCE-079 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "DNS Zone Transfer Attempt"
}

signature ZK-RECONNAISSANCE-080 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Web Technology Fingerprinting"
}

signature ZK-RECONNAISSANCE-081 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Cloud Asset Enumeration"
}

signature ZK-RECONNAISSANCE-082 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "SSL/TLS Certificate Reconnaissance"
}

signature ZK-RECONNAISSANCE-083 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "API Endpoint Discovery"
}

signature ZK-RECONNAISSANCE-084 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Email Harvesting & Phishing Prep"
}

signature ZK-RECONNAISSANCE-085 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "SNMP Community String Brute Force"
}

signature ZK-RECONNAISSANCE-086 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\/admin|\/phpinfo|\/\.env|\/\.git|\/wp\-admin|\/server\-status)).*/ regex
	event "Kubernetes API Server Recon"
}
