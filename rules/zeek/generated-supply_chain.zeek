# Zeek SIEM Alert Rules — generated-supply_chain
# Auto-generated: 2026-10-04T06:00:40.867193Z
# Load in local.zeek: @load ./generated-supply_chain

signature ZK-SUPPLY_CHAIN-057 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Dependency Confusion Attack"
}

signature ZK-SUPPLY_CHAIN-058 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Typosquatting Package Install"
}

signature ZK-SUPPLY_CHAIN-059 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Compromised CI/CD Pipeline"
}

signature ZK-SUPPLY_CHAIN-060 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Malicious NPM/PyPI Package"
}

signature ZK-SUPPLY_CHAIN-061 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Container Image Tampering"
}

signature ZK-SUPPLY_CHAIN-062 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Compromised Update Server"
}

signature ZK-SUPPLY_CHAIN-063 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Build Pipeline Injection"
}

signature ZK-SUPPLY_CHAIN-064 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Secret Leakage in CI Logs"
}

signature ZK-SUPPLY_CHAIN-065 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Unsigned Artifact Deployment"
}

signature ZK-SUPPLY_CHAIN-066 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(supply_chain).*/ regex
	event "Dependency Version Pinning Bypass"
}

signature ZK-SUPPLY_CHAIN-037 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Dependency Confusion Attack"
}

signature ZK-SUPPLY_CHAIN-038 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Typosquatting Package Install"
}

signature ZK-SUPPLY_CHAIN-039 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Compromised CI/CD Pipeline"
}

signature ZK-SUPPLY_CHAIN-040 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Malicious NPM/PyPI Package"
}

signature ZK-SUPPLY_CHAIN-041 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Container Image Tampering"
}

signature ZK-SUPPLY_CHAIN-042 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Compromised Update Server"
}

signature ZK-SUPPLY_CHAIN-043 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Build Pipeline Injection"
}

signature ZK-SUPPLY_CHAIN-044 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Secret Leakage in CI Logs"
}

signature ZK-SUPPLY_CHAIN-045 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Unsigned Artifact Deployment"
}

signature ZK-SUPPLY_CHAIN-046 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((npm\ install|pip\ install)).*/ regex
	event "Dependency Version Pinning Bypass"
}
