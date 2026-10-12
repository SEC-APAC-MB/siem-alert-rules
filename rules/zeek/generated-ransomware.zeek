# Zeek SIEM Alert Rules — generated-ransomware
# Auto-generated: 2026-10-12T06:00:32.459108Z
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

signature ZK-RANSOMWARE-057 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Mass File Encryption Pattern"
}

signature ZK-RANSOMWARE-058 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Shadow Copy Deletion"
}

signature ZK-RANSOMWARE-059 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Ransom Note Creation"
}

signature ZK-RANSOMWARE-060 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Volume Shadow Copy Tampering"
}

signature ZK-RANSOMWARE-061 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Backup Deletion via Vssadmin"
}

signature ZK-RANSOMWARE-062 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Ransomware C2 Beacon Pattern"
}

signature ZK-RANSOMWARE-063 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Mimikatz Credential Dumping Pre-Encryption"
}

signature ZK-RANSOMWARE-064 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Lateral Movement via PsExec/WMI"
}

signature ZK-RANSOMWARE-065 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Scheduled Task Creation for Encryption"
}

signature ZK-RANSOMWARE-066 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Registry Run Key Persistence for Ransomware"
}

signature ZK-RANSOMWARE-037 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Mass File Encryption Pattern"
}

signature ZK-RANSOMWARE-038 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Shadow Copy Deletion"
}

signature ZK-RANSOMWARE-039 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Ransom Note Creation"
}

signature ZK-RANSOMWARE-040 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Volume Shadow Copy Tampering"
}

signature ZK-RANSOMWARE-041 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Backup Deletion via Vssadmin"
}

signature ZK-RANSOMWARE-042 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Ransomware C2 Beacon Pattern"
}

signature ZK-RANSOMWARE-043 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Mimikatz Credential Dumping Pre-Encryption"
}

signature ZK-RANSOMWARE-044 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Lateral Movement via PsExec/WMI"
}

signature ZK-RANSOMWARE-045 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Scheduled Task Creation for Encryption"
}

signature ZK-RANSOMWARE-046 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*((vssadmin\ delete|wbadmin\ delete|bcdedit|cipher\ \/e|\.encrypted|\.locked)).*/ regex
	event "Registry Run Key Persistence for Ransomware"
}
