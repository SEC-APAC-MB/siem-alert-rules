# Zeek SIEM Alert Rules — generated-mobile_security
# Auto-generated: 2026-09-20T04:05:05.803552Z
# Load in local.zeek: @load ./generated-mobile_security

signature ZK-MOBILE_SECURITY-097 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mobile_security).*/ regex
	event "App Repackaging Detection"
}

signature ZK-MOBILE_SECURITY-098 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mobile_security).*/ regex
	event "Certificate Pinning Bypass"
}

signature ZK-MOBILE_SECURITY-099 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mobile_security).*/ regex
	event "API Traffic Tampering"
}

signature ZK-MOBILE_SECURITY-100 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mobile_security).*/ regex
	event "Root/Jailbreak Detection Bypass"
}
