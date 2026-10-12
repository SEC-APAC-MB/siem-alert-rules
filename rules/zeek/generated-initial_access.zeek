# Zeek SIEM Alert Rules — generated-initial_access
# Auto-generated: 2026-10-12T06:00:32.458312Z
# Load in local.zeek: @load ./generated-initial_access

signature ZK-INITIAL_ACCESS-087 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "Phishing Link Detection"
}

signature ZK-INITIAL_ACCESS-088 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "Spear-Phishing Attachment"
}

signature ZK-INITIAL_ACCESS-089 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "Valid Account Abuse"
}

signature ZK-INITIAL_ACCESS-090 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "Exploit Public-Facing Application"
}

signature ZK-INITIAL_ACCESS-091 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "Supply Chain Compromise"
}

signature ZK-INITIAL_ACCESS-092 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "VPN Appliance Exploitation"
}

signature ZK-INITIAL_ACCESS-093 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "Trusted Relationship Abuse"
}

signature ZK-INITIAL_ACCESS-094 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "Drive-by Compromise"
}

signature ZK-INITIAL_ACCESS-095 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "External Remote Services Brute Force"
}

signature ZK-INITIAL_ACCESS-096 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((login|auth|admin)).*/ regex
	event "Hardware Additions"
}
