# Zeek SIEM Alert Rules — generated-mobile_security
# Auto-generated: 2026-10-07T04:05:05.398024Z
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

signature ZK-MOBILE_SECURITY-077 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "App Repackaging Detection"
}

signature ZK-MOBILE_SECURITY-078 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "Certificate Pinning Bypass"
}

signature ZK-MOBILE_SECURITY-079 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "API Traffic Tampering"
}

signature ZK-MOBILE_SECURITY-080 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "Root/Jailbreak Detection Bypass"
}

signature ZK-MOBILE_SECURITY-081 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "Debuggable App in Production"
}

signature ZK-MOBILE_SECURITY-082 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "Insecure Data Storage"
}

signature ZK-MOBILE_SECURITY-083 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "Intent Redirection Attack"
}

signature ZK-MOBILE_SECURITY-084 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "Clipboard Data Leakage"
}

signature ZK-MOBILE_SECURITY-085 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "Insecure WebView Implementation"
}

signature ZK-MOBILE_SECURITY-086 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((Mobile|Android|iPhone)).*/ regex
	event "Biometric Auth Bypass"
}
