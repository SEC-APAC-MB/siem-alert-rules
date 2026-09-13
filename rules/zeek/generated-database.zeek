# Zeek SIEM Alert Rules — generated-database
# Auto-generated: 2026-09-13T22:00:56.749791Z
# Load in local.zeek: @load ./generated-database

signature ZK-DATABASE-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-21962).*/ regex
	event "CVE-2026-21962 — HTTP Server and Oracle Weblogic Server Proxy Plug-in Exploitation"
}

signature ZK-DATABASE-009 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2019\-1068).*/ regex
	event "CVE-2019-1068 — SQL Server Exploitation"
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

signature ZK-DATABASE-018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2019\-1068).*/ regex
	event "CVE-2019-1068 — SQL Server Exploitation"
}

signature ZK-DATABASE-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2026\-21962).*/ regex
	event "CVE-2026-21962 — HTTP Server and Oracle Weblogic Server Proxy Plug-in Exploitation"
}

signature ZK-DATABASE-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /.*(cve\-2019\-1068).*/ regex
	event "CVE-2019-1068 — SQL Server Exploitation"
}
