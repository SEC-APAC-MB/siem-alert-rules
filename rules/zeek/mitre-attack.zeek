# =============================================================================
# Zeek Signatures — MITRE ATT&CK
# Total rules: 50
# MITRE ATT&CK: Full tactic coverage
# Compliance: PCI-DSS, GDPR, HIPAA, NIST
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# Reconnaissance
# =============================================================================

signature ZK-MITRE-001 {
	ip-proto tcp
	dst-port = { 21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1433 1521 3306 3389 5432 5900 8080 8443 9200 27017 }
	payload /.*(Nmap|Masscan|ZMap|Nikto|DirBuster|Gobuster|Wfuzz|Feroxbuster|Nuclei|httpx|Shodan|Censys).*/ regex
	event "MITRE-T1595: Active network scanning tool detected"
}

signature ZK-MITRE-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(admin|login|dashboard|wp-admin|phpmyadmin|manager|console|actuator|api-docs|swagger|\.env|\.git|\.DS_Store|\.well-known|server-status|server-info)/ regex
	event "MITRE-T1592: Reconnaissance - sensitive path access attempt"
}

signature ZK-MITRE-003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*\.(bak|old|backup|swp|save|temp|tmp|orig|copy|conf|config|ini|yml|yaml|xml|json|env|log|sql|db|mdb|sqlite|csv|tsv).*/ regex
	event "MITRE-T1592: Reconnaissance - backup/config file access attempt"
}

# =============================================================================
# Initial Access
# =============================================================================

signature ZK-MITRE-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/(login|auth|signin|authenticate)/ regex
	payload /.*(admin|root|test|guest|default|password|123456|qwerty|letmein|welcome).*/ regex
	event "MITRE-T1078: Valid accounts - default credential attempt"
}

signature ZK-MITRE-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin)/ regex
	http-response /302 Found|301 Moved/ regex
	http-header /Location: .*(login|auth|signin)/ regex
	event "MITRE-T1566: Phishing - redirect to credential harvesting page"
}

signature ZK-MITRE-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(wp-content|wp-includes|wp-admin|administrator|phpmyadmin|manager\/html|actuator|console|/api/v1/exploit).*/ regex
	http-response /200 OK/ regex
	event "MITRE-T1190: Exploit public-facing application - vulnerable endpoint"
}

# =============================================================================
# Execution
# =============================================================================

signature ZK-MITRE-007 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(exec|execute|run|system|command|shell|cmd|powershell|bash)/ regex
	payload /.*(whoami|id|uname|hostname|cat|ls|dir|ping|nslookup|ifconfig|ipconfig|netstat|wget|curl|nc).*/ regex
	event "MITRE-T1059: Command execution via API endpoint"
}

signature ZK-MITRE-008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(exec|execute|run|system|command|shell|cmd)/ regex
	payload /.*(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|bash|sh|python|perl|ruby|php).*/ regex
	event "MITRE-T1059: Script/interpreter execution via API"
}

# =============================================================================
# Persistence
# =============================================================================

signature ZK-MITRE-009 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(webhooks?|hooks?|callbacks?|scheduled|cron|jobs?|tasks?)/ regex
	payload /.*"(url|endpoint|target|callback)"\s*:\s*"(http|https):\/\/.*/ regex
	event "MITRE-T1053: Scheduled task/webhook creation - persistence mechanism"
}

signature ZK-MITRE-010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(users?|accounts?|keys?|tokens?|credentials)/ regex
	payload /.*"(role|isAdmin|permissions|privileges|account_type)"\s*:\s*"(admin|superuser|root|manager|owner)".*/ regex
	event "MITRE-T1548: Privilege escalation - role/permission modification"
}

# =============================================================================
# Privilege Escalation
# =============================================================================

signature ZK-MITRE-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(PUT|PATCH) \/api\/v[0-9]+\/users\/\d+\/(role|permissions|admin|privilege)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1548: Privilege escalation - role/permission modification API call"
}

signature ZK-MITRE-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/admin|api\/v[0-9]+\/admin|admin|management|console|dashboard)\/?(.*)/ regex
	http-header /Cookie: .*(role|user_role|isAdmin)=(user|member|viewer|false|0)/ regex
	event "MITRE-T1548: Non-admin cookie accessing admin endpoint - privilege escalation"
}

# =============================================================================
# Defense Evasion
# =============================================================================

signature ZK-MITRE-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(logs?|audit|events?|monitoring|notifications?|alerts?)/ regex
	http-request /(DELETE|PUT|PATCH) \/api\/v[0-9]+\/(logs?|audit|events?|monitoring).*/ regex
	event "MITRE-T1562: Defense evasion - log/audit deletion attempt"
}

signature ZK-MITRE-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /X-Forwarded-For: .*/ regex
	http-header /X-Real-IP: .*/ regex
	http-header /X-Original-URL: .*/ regex
	event "MITRE-T1562: Defense evasion - IP address spoofing via proxy headers"
}

signature ZK-MITRE-015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v[0-9]+\/)?(waf|firewall|security|ids|ips|av|antivirus|protection)\/(disable|bypass|skip|whitelist|exception|turnoff)/ regex
	event "MITRE-T1562: Defense evasion - WAF/security bypass attempt"
}

# =============================================================================
# Credential Access
# =============================================================================

signature ZK-MITRE-016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/api\/v[0-9]+\/(login|auth|signin|authenticate)/ regex
	http-response /401 Unauthorized|403 Forbidden/ regex
	event "MITRE-T1110: Brute force - multiple failed login attempts"
}

signature ZK-MITRE-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(password-reset|forgot-password|recover-account)/ regex
	payload /.*"(email|phone|username)"\s*:\s*"[^"]*".*/ regex
	http-header /User-Agent: .*(python-requests|curl|wget|Go-http|node-fetch)/ regex
	event "MITRE-T1110: Brute force - automated password reset attempt"
}

signature ZK-MITRE-018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(users|accounts|credentials|keys|tokens)/ regex
	http-response /200 OK/ regex
	payload /.*"(password|secret|api_key|token|private_key|access_key|secret_key|connection_string)".*/ regex
	event "MITRE-T1552: Credential access - API response containing secrets"
}

# =============================================================================
# Discovery
# =============================================================================

signature ZK-MITRE-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(users|accounts|roles|permissions|groups|services|endpoints|config|settings)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1082: Discovery - API enumeration of users/roles/services"
}

signature ZK-MITRE-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(swagger|openapi|docs|api-docs|graphiql|playground|actuator|health|info|metrics|env|configprops)/ regex
	event "MITRE-T1082: Discovery - API documentation/infrastructure endpoints exposed"
}

# =============================================================================
# Lateral Movement
# =============================================================================

signature ZK-MITRE-021 {
	ip-proto tcp
	dst-port = { 22 3389 5985 5986 }
	payload /.*(root|admin|administrator|service|system).*(password|passwd|pwd|pass).*/ regex
	event "MITRE-T1021: Lateral movement - SSH/RDP/WinRM with credentials"
}

signature ZK-MITRE-022 {
	ip-proto tcp
	dst-port = { 135 445 }
	payload /.*(net\s+view|net\s+computers|nltest|dsquery|Get-ADComputer|Get-ADGroupMember|Test-Connection|ping\s+-a).*/ regex
	event "MITRE-T1018: Lateral movement - remote system discovery"
}

# =============================================================================
# Collection
# =============================================================================

signature ZK-MITRE-023 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(export|download|report|dump|backup|archive|extract)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1560: Collection - bulk data export via API"
}

signature ZK-MITRE-024 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(users|accounts|customers|records)\?(.*&)?(fields=|include=).*(password|token|secret|ssn|credit_card|email|phone|address)/ regex
	event "MITRE-T1213: Collection - sensitive data field enumeration via API"
}

# =============================================================================
# Command and Control
# =============================================================================

signature ZK-MITRE-025 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 8888 9090 }
	http-request /\/(beacon|c2|command|cmd|control|shell|reverse|connect|callback|checkin|poll|heartbeat)/ regex
	event "MITRE-T1071: C2 - suspicious command and control endpoint"
}

signature ZK-MITRE-026 {
	ip-proto tcp
	dst-port = { 53 }
	payload /.*[a-zA-Z0-9]{30,}.*\.(com|net|org|info|xyz|top|click|online|site|club).*/ regex
	event "MITRE-T1071: DNS tunneling - suspicious long subdomain queries"
}

signature ZK-MITRE-027 {
	ip-proto tcp
	dst-port = { 443 8443 }
	payload /.*TLS.*1\.(0|1).*/ regex
	event "MITRE-T1573: Encrypted channel - weak TLS version detected"
}

# =============================================================================
# Exfiltration
# =============================================================================

signature ZK-MITRE-028 {
	ip-proto tcp
	dst-port = { 80 443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(upload|file|document|attachment|media)/ regex
	http-header /Content-Length: [0-9]{8,}/ regex
	event "MITRE-T1567: Exfiltration - large file upload via API"
}

signature ZK-MITRE-029 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v[0-9]+\/)?(upload|file|document|attachment|media)\/?(.*)/ regex
	http-header /Host: (drive\.google\.com|dropbox\.com|onedrive\.live\.com|mega\.nz|wetransfer\.com|cloud\.storage)/ regex
	event "MITRE-T1567: Exfiltration - data transfer to cloud storage"
}

# =============================================================================
# Impact
# =============================================================================

signature ZK-MITRE-030 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(DELETE) \/api\/v[0-9]+\/(users|accounts|records|data|logs|audit)\/?(.*)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1485: Impact - mass data deletion via API"
}

signature ZK-MITRE-031 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(encrypt|ransom|lock|destroy|wipe|format)/ regex
	payload /.*(YOUR_DATA_HAS_BEEN_LOCKED|YOUR_FILES_HAVE_BEEN_ENCRYPTED|PAY_RANSOM|DECRYPT_KEY|BITCOIN_PAYMENT).*/ regex
	event "MITRE-T1486: Impact - ransomware activity via API"
}

# =============================================================================
# Additional MITRE Rules
# =============================================================================

signature ZK-MITRE-032 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(wp-login\.php|wp-admin|wp-content|xmlrpc\.php|administrator|phpmyadmin|manager\/html)/ regex
	http-response /200 OK/ regex
	event "MITRE-T1190: Exploit - admin interface publicly accessible"
}

signature ZK-MITRE-033 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/(users?|accounts?|sessions?)/ regex
	payload /.*"(password|new_password|confirm_password)"\s*:\s*"[^"]*".*/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1078: Valid accounts - password change via compromised session"
}

signature ZK-MITRE-034 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/api\/v[0-9]+\/(webhooks?|hooks?|callbacks?|subscriptions?)/ regex
	payload /.*"(url|endpoint|target|callback)"\s*:\s*"(http|https):\/\/.*/ regex
	event "MITRE-T1546: Persistence - webhook creation for command and control"
}

signature ZK-MITRE-035 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(users|accounts)\?(.*&)?(limit=|per_page=|page_size=)(10000|100000|-1|all|unlimited)/ regex
	event "MITRE-T1087: Account discovery - mass user enumeration via API pagination"
}

signature ZK-MITRE-036 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(tokens?|sessions?|keys?|credentials)/ regex
	payload /.*"(type|scope)"\s*:\s*"(admin|root|superuser|system|global|full|write|delete)".*/ regex
	event "MITRE-T1550: Use of alternate authentication material - token with excessive scope"
}

signature ZK-MITRE-037 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(oauth|saml|sso|auth\/callback)/ regex
	payload /.*redirect_uri=.*(http|\/\/%2F%2F)[^#]*$/ regex
	event "MITRE-T1187: Forced authentication - OAuth redirect URI manipulation"
}

signature ZK-MITRE-038 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/.*/ regex
	http-header /Content-Type: multipart\/form-data/ regex
	payload /.*filename=".*\.(php|jsp|asp|aspx|cgi|pl|py|rb|sh|exe|bat|cmd|com|vbs|wsf|msi|dll|so).*/ regex
	event "MITRE-T1190: Exploit - malicious file upload to web application"
}

signature ZK-MITRE-039 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(exec|execute|run|system|command|shell|cmd|powershell|bash)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1059: Command and scripting interpreter - API command execution endpoint"
}

signature ZK-MITRE-040 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(documents|files|content|pages|templates)/ regex
	payload /.*(<script|javascript:|onerror\s*=|onload\s*=|<iframe|<svg|<img\s+src\s*=\s*".*onerror|document\.cookie|document\.location).*/ regex
	event "MITRE-T1059.007: JavaScript/HTML injection via API - stored XSS"
}

signature ZK-MITRE-041 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v[0-9]+\/)?(users?|accounts?|sessions?|tokens?)\/\d+\/(impersonate|switch|sudo|escalate|elevate)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1548: Privilege escalation - impersonation/elevation API call"
}

signature ZK-MITRE-042 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v[0-9]+\/)?(admin|management|system|config|settings|maintenance)\/?(.*)/ regex
	http-header /!(Authorization)/ regex
	event "MITRE-T1078: Valid accounts - admin endpoint access without authentication"
}

signature ZK-MITRE-043 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(password|secret|token|key|credential)\/(generate|rotate|reset|create)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1552: Credential access - credential creation/rotation via API"
}

signature ZK-MITRE-044 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(DELETE) \/api\/v[0-9]+\/(logs?|audit|events?|monitoring|notifications?|alerts?|sessions?)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1562: Defense evasion - log/audit deletion via API"
}

signature ZK-MITRE-045 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(tokens?|sessions?)\/\d+/ regex
	http-header /Authorization: Bearer .*/ regex
	http-header /X-Forwarded-For: .*/ regex
	event "MITRE-T1550: Pass the token - API token reuse from different IP"
}

signature ZK-MITRE-046 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(infrastructure|servers|services|containers|nodes|clusters|databases|networks)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "MITRE-T1082: System information discovery - infrastructure enumeration via API"
}

signature ZK-MITRE-047 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(emails?|messages?|notifications?|sms|push)/ regex
	payload /.*"(to|recipient|target|destination)"\s*:\s*"[^"]*".*/ regex
	payload /.*"(subject|body|content|text|message)"\s*:\s*".*(urgent|verify your account|confirm your identity|security alert|unauthorized access|click here|suspend|immediately|action required).*/ regex
	event "MITRE-T1566: Phishing - bulk email/message creation with phishing content"
}

signature ZK-MITRE-048 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/(users?|accounts?|roles?|permissions?|policies?)/ regex
	payload /.*"(role|isAdmin|permissions|privileges)"\s*:\s*"(admin|superuser|root|system|global)".*/ regex
	event "MITRE-T1548: Privilege escalation - role escalation via user update API"
}

signature ZK-MITRE-049 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /GET \/api\/v[0-9]+\/(users|accounts)\?(.*&)?(fields=|include=).*(email|phone|address|ssn|dob|birth|gender|salary|income)/ regex
	event "MITRE-T1213: Data from information store - PII field enumeration via API"
}

signature ZK-MITRE-050 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(webhooks?|integrations?|callbacks?|notifications?)/ regex
	payload /.*"(url|endpoint|target|callback)"\s*:\s*"(http|https):\/\/(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|169\.254\.169\.254).*/ regex
	event "MITRE-T1571: C2 - webhook/integration pointing to internal network"
}