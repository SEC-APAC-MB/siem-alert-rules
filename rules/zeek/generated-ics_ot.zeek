# Zeek SIEM Alert Rules — generated-ics_ot
# Auto-generated: 2026-10-10T04:05:05.393867Z
# Load in local.zeek: @load ./generated-ics_ot

signature ZK-ICS_OT-087 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "Modbus Command Injection"
}

signature ZK-ICS_OT-088 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "S7comm Firmware Upload"
}

signature ZK-ICS_OT-089 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "OPC UA Authentication Bypass"
}

signature ZK-ICS_OT-090 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "PLC Logic Modification"
}

signature ZK-ICS_OT-091 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "HMI Unauthorized Access"
}

signature ZK-ICS_OT-092 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "SCADA Protocol Anomaly"
}

signature ZK-ICS_OT-093 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "Engineering Workstation Compromise"
}

signature ZK-ICS_OT-094 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "Safety Instrumented System Tampering"
}

signature ZK-ICS_OT-095 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "ICS Network Scanning"
}

signature ZK-ICS_OT-096 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((modbus|dnp3|opcua|s7comm)).*/ regex
	event "Historian Database Manipulation"
}
