# Zeek SIEM Alert Rules — generated-reconnaissance
# Auto-generated: 2026-10-10T04:05:05.398152Z
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
