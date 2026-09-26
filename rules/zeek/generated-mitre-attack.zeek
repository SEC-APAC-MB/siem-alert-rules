# Zeek SIEM Alert Rules — generated-mitre-attack
# Auto-generated: 2026-09-25T04:05:13.165524Z
# Load in local.zeek: @load ./generated-mitre-attack

signature ZK-MITRE-ATTACK-021 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1055.011: Extra Window Memory Injection"
}

signature ZK-MITRE-ATTACK-022 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1053.005: Scheduled Task"
}

signature ZK-MITRE-ATTACK-023 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1205.002: Socket Filters"
}

signature ZK-MITRE-ATTACK-024 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1560.001: Archive via Utility"
}

signature ZK-MITRE-ATTACK-025 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1021.005: VNC"
}

signature ZK-MITRE-ATTACK-026 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1047: Windows Management Instrumentation"
}

signature ZK-MITRE-ATTACK-027 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1687: Exploitation for Defense Impairment"
}

signature ZK-MITRE-ATTACK-028 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1113: Screen Capture"
}

signature ZK-MITRE-ATTACK-029 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1027.011: Fileless Storage"
}

signature ZK-MITRE-ATTACK-030 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1037: Boot or Logon Initialization Scripts"
}

signature ZK-MITRE-ATTACK-031 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1557: Adversary-in-the-Middle"
}

signature ZK-MITRE-ATTACK-032 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1033: System Owner/User Discovery"
}

signature ZK-MITRE-ATTACK-033 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1583: Acquire Infrastructure"
}

signature ZK-MITRE-ATTACK-034 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1218.011: Rundll32"
}

signature ZK-MITRE-ATTACK-035 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1613: Container and Resource Discovery"
}

signature ZK-MITRE-ATTACK-036 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1583.007: Serverless"
}

signature ZK-MITRE-ATTACK-037 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1132.001: Standard Encoding"
}

signature ZK-MITRE-ATTACK-038 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1027.009: Embedded Payloads"
}

signature ZK-MITRE-ATTACK-039 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1556.003: Pluggable Authentication Modules"
}

signature ZK-MITRE-ATTACK-040 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(mitre\-attack).*/ regex
	event "MITRE T1578.004: Revert Cloud Instance"
}
