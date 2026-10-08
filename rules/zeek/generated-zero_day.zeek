# Zeek SIEM Alert Rules — generated-zero_day
# Auto-generated: 2026-10-08T04:05:05.060016Z
# Load in local.zeek: @load ./generated-zero_day

signature ZK-ZERO_DAY-087 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Unexpected Process Execution from Web Directory"
}

signature ZK-ZERO_DAY-088 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Anomalous Child Process from Service"
}

signature ZK-ZERO_DAY-089 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Unusual Network Connection from System Process"
}

signature ZK-ZERO_DAY-090 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Memory Injection Pattern Detection"
}

signature ZK-ZERO_DAY-091 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Unexpected DLL Loading"
}

signature ZK-ZERO_DAY-092 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Abnormal Token Privilege Elevation"
}

signature ZK-ZERO_DAY-093 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Process Hollowing Indicator"
}

signature ZK-ZERO_DAY-094 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Reflective DLL Injection"
}

signature ZK-ZERO_DAY-095 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Unusual Named Pipe Activity"
}

signature ZK-ZERO_DAY-096 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(zero_day).*/ regex
	event "Anomalous Service Installation"
}

signature ZK-ZERO_DAY-067 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Unexpected Process Execution from Web Directory"
}

signature ZK-ZERO_DAY-068 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Anomalous Child Process from Service"
}

signature ZK-ZERO_DAY-069 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Unusual Network Connection from System Process"
}

signature ZK-ZERO_DAY-070 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Memory Injection Pattern Detection"
}

signature ZK-ZERO_DAY-071 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Unexpected DLL Loading"
}

signature ZK-ZERO_DAY-072 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Abnormal Token Privilege Elevation"
}

signature ZK-ZERO_DAY-073 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Process Hollowing Indicator"
}

signature ZK-ZERO_DAY-074 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Reflective DLL Injection"
}

signature ZK-ZERO_DAY-075 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Unusual Named Pipe Activity"
}

signature ZK-ZERO_DAY-076 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((\.cgi|\.php|\.asp)).*/ regex
	event "Anomalous Service Installation"
}
