# Zeek SIEM Alert Rules — generated-database
# Auto-generated: 2026-09-26T04:05:06.156775Z
# Load in local.zeek: @load ./generated-database

signature ZK-DATABASE-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-21962).*/ regex
	event "CVE-2026-21962 — HTTP Server and Oracle Weblogic Server Proxy Plug-in Exploitation"
}

signature ZK-DATABASE-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-21962).*/ regex
	event "CVE-2026-21962 — HTTP Server and Oracle Weblogic Server Proxy Plug-in Exploitation"
}

signature ZK-DATABASE-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-21962).*/ regex
	event "CVE-2026-21962 — HTTP Server and Oracle Weblogic Server Proxy Plug-in Exploitation"
}

signature ZK-DATABASE-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-21962).*/ regex
	event "CVE-2026-21962 — HTTP Server and Oracle Weblogic Server Proxy Plug-in Exploitation"
}
