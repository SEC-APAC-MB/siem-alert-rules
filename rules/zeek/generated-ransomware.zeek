# Zeek SIEM Alert Rules — generated-ransomware
# Auto-generated: 2026-09-19T04:05:04.247673Z
# Load in local.zeek: @load ./generated-ransomware

signature ZK-RANSOMWARE-077 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Mass File Encryption Pattern"
}

signature ZK-RANSOMWARE-078 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Shadow Copy Deletion"
}

signature ZK-RANSOMWARE-079 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Ransom Note Creation"
}

signature ZK-RANSOMWARE-080 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Volume Shadow Copy Tampering"
}

signature ZK-RANSOMWARE-081 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Backup Deletion via Vssadmin"
}

signature ZK-RANSOMWARE-082 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Ransomware C2 Beacon Pattern"
}

signature ZK-RANSOMWARE-083 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Mimikatz Credential Dumping Pre-Encryption"
}

signature ZK-RANSOMWARE-084 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Lateral Movement via PsExec/WMI"
}

signature ZK-RANSOMWARE-085 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Scheduled Task Creation for Encryption"
}

signature ZK-RANSOMWARE-086 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(ransomware).*/ regex
	event "Registry Run Key Persistence for Ransomware"
}
