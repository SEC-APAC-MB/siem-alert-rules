# =============================================================================
# Zeek Signatures — WSTG 07-09 (Input Validation, Error Handling, Cryptography)
# Total rules: 42
# MITRE ATT&CK: T1190, T1059, T1187, T1040, T1552
# Compliance: PCI-DSS 6.5, GDPR 32, HIPAA 164.312, NIST SI-4, SC-8
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# WSTG-INPV-01: SQL Injection
# =============================================================================

signature ZK-WSTG0701 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*=(.*('|%27)(|%20)*(OR|AND|%20OR%20|%20AND%20)(|%20)*(1|true|%271%27|%27true%27)).*/ regex
	event "WSTG-INPV-01: SQL injection - boolean-based tautology detected"
}

signature ZK-WSTG0702 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(UNION(%20|%2B)(ALL)?(%20|%2B)SELECT|UNION%20ALL%20SELECT|UNION%20SELECT).*/ regex
	event "WSTG-INPV-01: SQL injection - UNION SELECT detected"
}

signature ZK-WSTG0703 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(;|%3B)(DROP|ALTER|CREATE|INSERT|UPDATE|DELETE|TRUNCATE)(%20|%2B)(TABLE|DATABASE|USER|INDEX).*/ regex
	event "WSTG-INPV-01: SQL injection - DDL/DML statement after semicolon"
}

signature ZK-WSTG0704 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(SLEEP%28|BENCHMARK%28|WAITFOR%20DELAY|PG_SLEEP|DBMS_PIPE\.RECEIVE_MESSAGE).*/ regex
	event "WSTG-INPV-01: SQL injection - time-based blind detected"
}

signature ZK-WSTG0705 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(OR%201%3D1|AND%201%3D1|%27%20OR%20%271%27%3D%271|%22%20OR%20%22|%27%20--|%27%20--|1%3D1--).*/ regex
	event "WSTG-INPV-01: SQL injection - classic OR 1=1 tautology"
}

signature ZK-WSTG0706 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(EXTRACTVALUE|UPDATEXML|XMLPATH|CONCAT|GROUP_CONCAT|INFORMATION_SCHEMA|SYS\.|MYSQL\.|PG_|DBA_|SYS\.).*/ regex
	event "WSTG-INPV-01: SQL injection - error-based extraction functions"
}

# =============================================================================
# WSTG-INPV-02: XSS (Cross-Site Scripting)
# =============================================================================

signature ZK-WSTG0707 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(%3Cscript|%3CScript|<script|<Script|<SCRIPT).*(%3E|>|%3e).*/ regex
	event "WSTG-INPV-02: Reflected XSS - script tag injection detected"
}

signature ZK-WSTG0708 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(%3Cimg|<img|%3cimg).*(onerror|onload|onclick|onmouseover).*(%3E|>|%3e).*/ regex
	event "WSTG-INPV-02: XSS - image tag with event handler injection"
}

signature ZK-WSTG0709 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(javascript%3A|javascript:|vbscript%3A|vbscript:|data%3Atext\/html|data:text\/html).*/ regex
	event "WSTG-INPV-02: XSS - JavaScript/VBScript/data URI injection"
}

signature ZK-WSTG0710 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(%3Csvg|<svg|%3csvg).*(onload|onerror|onclick|onmouseover).*(%3E|>|%3e).*/ regex
	event "WSTG-INPV-02: XSS - SVG tag with event handler injection"
}

signature ZK-WSTG0711 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(%3Ciframe|<iframe|%3ciframe).*(src|onload).*(%3E|>|%3e).*/ regex
	event "WSTG-INPV-02: XSS - iframe injection detected"
}

signature ZK-WSTG0712 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(on(error|load|click|mouseover|focus|blur|submit|change)=%22|%22on(error|load|click|mouseover)=%22|on(error|load|click)='|'on(error|load|click)=').*/ regex
	event "WSTG-INPV-02: XSS - HTML event handler attribute injection"
}

signature ZK-WSTG0713 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(%3Cbody|<body|%3cbody).*(onload|onerror|onfocus|onmouseover).*(%3E|>|%3e).*/ regex
	event "WSTG-INPV-02: XSS - body tag with event handler injection"
}

# =============================================================================
# WSTG-INPV-03: Command Injection
# =============================================================================

signature ZK-WSTG0714 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(;|%3B|%26|%7C|`|%60|\|%5C).*(ls|cat|id|whoami|pwd|uname|ifconfig|ipconfig|netstat|ping|wget|curl|nc).*/ regex
	event "WSTG-INPV-03: OS command injection detected"
}

signature ZK-WSTG0715 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(\|%7C).*(ls|cat|id|whoami|pwd|uname|ifconfig|ipconfig|netstat).*/ regex
	event "WSTG-INPV-03: OS command injection via pipe operator"
}

signature ZK-WSTG0716 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(\$%28|%28%29|`|%60).*(whoami|id|uname|hostname|cat|ls|pwd).*/ regex
	event "WSTG-INPV-03: OS command injection via command substitution"
}

signature ZK-WSTG0717 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(\n|%0a|\r|%0d).*(cat|ls|id|whoami|pwd|uname|/bin/sh|/bin/bash).*/ regex
	event "WSTG-INPV-03: OS command injection via newline injection"
}

# =============================================================================
# WSTG-INPV-04: Path Traversal
# =============================================================================

signature ZK-WSTG0718 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c).*(etc\/passwd|etc\/shadow|windows\/system32|boot\.ini|win\.ini|web\.config|\.htaccess).*/ regex
	event "WSTG-INPV-04: Path traversal targeting system files"
}

signature ZK-WSTG0719 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f).*(\.env|\.git|\.svn|\.htaccess|\.DS_Store|web\.config|database\.yml|config\.php|settings\.py).*/ regex
	event "WSTG-INPV-04: Path traversal targeting configuration files"
}

signature ZK-WSTG0720 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\.\.%2f|%2e%2e\/|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f).*/ regex
	event "WSTG-INPV-04: Path traversal with double encoding detected"
}

# =============================================================================
# WSTG-INPV-05: NoSQL Injection
# =============================================================================

signature ZK-WSTG0721 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(\$where|\$gt|\$gte|\$lt|\$lte|\$ne|\$in|\$nin|\$regex|\$expr|\$jsonSchema).*/ regex
	event "WSTG-INPV-05: NoSQL injection operator detected"
}

signature ZK-WSTG0722 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/.*(query|search|find|filter|where).*/ regex
	payload /.*\{\s*"\$where"\s*:.*\}.*|\{\s*"\$gt"\s*:.*\}.*|\{\s*"\$regex"\s*:.*\}.*/ regex
	event "WSTG-INPV-05: NoSQL injection via MongoDB query operators"
}

# =============================================================================
# WSTG-INPV-06: SSRF (Server-Side Request Forgery)
# =============================================================================

signature ZK-WSTG0723 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(url=|callback=|redirect=|next=|dest=|target=|return=|path=|file=|page=|feed=|reference=).*(http|https|ftp|file|gopher):\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|10\.|192\.168|172\.(1[6-9]|2[0-9]|3[01])|169\.254|metadata\.google\.internal|169\.254\.169\.254).*/ regex
	event "WSTG-INPV-06: SSRF - internal/metadata URL access detected"
}

signature ZK-WSTG0724 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(url=|callback=|redirect=|next=|dest=|target=|path=|fetch=|link=|reference=).*(http|https|ftp|file|gopher):\/\/.*/ regex
	http-header /X-Forwarded-For: .*/ regex
	event "WSTG-INPV-06: SSRF - URL fetch parameter with potential internal access"
}

signature ZK-WSTG0725 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(url=|callback=|redirect=|next=|dest=|target=|path=).*(http|https):\/\/(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|localhost).*/ regex
	event "WSTG-INPV-06: SSRF - targeting internal RFC 1918 addresses"
}

# =============================================================================
# WSTG-INPV-07: XXE (XML External Entity)
# =============================================================================

signature ZK-WSTG0726 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) .*/ regex
	http-header /Content-Type: (application\/xml|text\/xml).*/ regex
	payload /.*<!DOCTYPE.*<!ENTITY.*SYSTEM.*>.*/ regex
	event "WSTG-INPV-07: XXE - external entity declaration in XML payload"
}

signature ZK-WSTG0727 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) .*/ regex
	http-header /Content-Type: (application\/xml|text\/xml).*/ regex
	payload /.*<!DOCTYPE.*<!ENTITY.*%(.*).*>.*/ regex
	event "WSTG-INPV-07: XXE - parameter entity declaration detected"
}

signature ZK-WSTG0728 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) .*/ regex
	http-header /Content-Type: (application\/xml|text\/xml).*/ regex
	payload /.*<!ENTITY.*SYSTEM\s+"(file|ftp|http|https|gopher):\/\/.*/ regex
	event "WSTG-INPV-07: XXE - SYSTEM entity with external URI detected"
}

# =============================================================================
# WSTG-INPV-08: File Upload
# =============================================================================

signature ZK-WSTG0729 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(upload|api\/upload|api\/files|api\/attachments|api\/media)/ regex
	http-header /Content-Type: multipart\/form-data/ regex
	payload /.*filename=".*\.(php|jsp|asp|aspx|cgi|pl|py|rb|sh|exe|bat|cmd|com|vbs|wsf|msi|dll|so).*/ regex
	event "WSTG-INPV-08: Malicious file upload - executable file extension"
}

signature ZK-WSTG0730 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(upload|api\/upload|api\/files|api\/attachments)/ regex
	http-header /Content-Type: multipart\/form-data/ regex
	payload /.*filename=".*\.(php\d*|phtml|phps|pht|phar|inc|shtml|stm|shtm).*/ regex
	event "WSTG-INPV-08: Malicious file upload - PHP double extension bypass"
}

signature ZK-WSTG0731 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(upload|api\/upload|api\/files|api\/attachments)/ regex
	http-header /Content-Type: multipart\/form-data/ regex
	payload /.*filename=".*\.(htaccess|web\.config|\.env|crossdomain\.xml|clientaccesspolicy\.xml).*/ regex
	event "WSTG-INPV-08: Malicious file upload - server configuration file"
}

signature ZK-WSTG0732 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/(upload|api\/upload|api\/files|api\/attachments)/ regex
	http-header /Content-Type: multipart\/form-data/ regex
	payload /.*Content-Type:.*(<?|<%|<script|<\?php).*/ regex
	event "WSTG-INPV-08: Malicious file upload - script content in file body"
}

# =============================================================================
# WSTG-ERRH-01: Error Handling
# =============================================================================

signature ZK-WSTG0733 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /500 Internal Server Error/ regex
	payload /.*(stack trace|Traceback \(most recent call last\)|Exception Details|at .*\.java:\d+|at .*\.py:\d+|at .*\.rb:\d+|in .*\.php.*line \d+).*/ regex
	event "WSTG-ERRH-01: Stack trace disclosure in 500 error response"
}

signature ZK-WSTG0734 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /500 Internal Server Error/ regex
	payload /.*(ORA-\d{5}|MySQL Error|PostgreSQL query failed|SQLSTATE\[|Microsoft OLE DB|Unclosed quotation mark|SQL error|ODBC SQL Server Driver).*/ regex
	event "WSTG-ERRH-01: Database error disclosure in error response"
}

signature ZK-WSTG0735 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /500 Internal Server Error/ regex
	payload /.*(\/home\/|\/usr\/|\/var\/|C:\\Users\\|C:\\inetpub\\|\/opt\/|\/etc\/|Application path|DOCUMENT_ROOT|SERVER_SOFTWARE).*/ regex
	event "WSTG-ERRH-01: Server path disclosure in error response"
}

signature ZK-WSTG0736 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /500 Internal Server Error/ regex
	payload /.*(debug mode|DEBUG=True|APP_DEBUG=true|config\.debug|stack frames|application error).*/ regex
	event "WSTG-ERRH-01: Debug mode information in error response"
}

# =============================================================================
# WSTG-CRYP-01: Weak Cryptography
# =============================================================================

signature ZK-WSTG0737 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie: .*(sessionid|session_id|PHPSESSID|JSESSIONID).*/ regex
	http-header /Set-Cookie: .*(?!(\bSecure\b)).*/ regex
	event "WSTG-CRYP-01: Session cookie transmitted over insecure channel - weak crypto"
}

signature ZK-WSTG0738 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Authorization: Basic .*/ regex
	event "WSTG-CRYP-01: Basic authentication used - credentials sent in base64"
}

signature ZK-WSTG0739 {
	ip-proto tcp
	dst-port = { 80 }
	http-header /Authorization: .*/ regex
	event "WSTG-CRYP-01: Credentials transmitted over unencrypted HTTP"
}

signature ZK-WSTG0740 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(password|passwd|pwd|secret|token|api_key|apikey|private_key)=.*/ regex
	event "WSTG-CRYP-01: Sensitive credentials in URL query string - unencrypted transmission"
}

# =============================================================================
# WSTG-CRYP-02: Padding Oracle
# =============================================================================

signature ZK-WSTG0741 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(token|data|cipher|iv|payload|enc)=.*/ regex
	http-response /.*(PaddingException|pad block corrupted|PKCS|bad padding|Invalid padding|decryption error|MAC verification failed).*/ regex
	event "WSTG-CRYP-02: Padding oracle error response detected"
}

# =============================================================================
# WSTG-CRYP-03: Sensitive Data in Transit
# =============================================================================

signature ZK-WSTG0742 {
	ip-proto tcp
	dst-port = { 80 }
	http-request /\/(login|auth|signin|register|password-reset|payment|checkout|account|profile|settings)/ regex
	event "WSTG-CRYP-03: Sensitive page accessed over unencrypted HTTP"
}

signature ZK-WSTG0743 {
	ip-proto tcp
	dst-port = { 80 }
	http-header /Set-Cookie: .*/ regex
	http-header /Set-Cookie: .*(?!(\bSecure\b)).*/ regex
	event "WSTG-CRYP-03: Cookie without Secure flag set on HTTP - insecure transit"
}

# =============================================================================
# WSTG-CRYP-04: Weak SSL/TLS
# =============================================================================

signature ZK-WSTG0744 {
	ip-proto tcp
	dst-port = { 443 }
	payload /.*TLS 1\.0|TLS 1\.1|SSLv3|SSLv2|SSLv23.*/ regex
	event "WSTG-CRYP-04: Weak TLS/SSL protocol version negotiated"
}

signature ZK-WSTG0745 {
	ip-proto tcp
	dst-port = { 443 }
	payload /.*(TLS_RSA_WITH_RC4|TLS_RSA_WITH_3DES|TLS_RSA_WITH_DES|TLS_RSA_EXPORT|TLS_DHE_RSA_EXPORT|TLS_RSA_WITH_NULL|TLS_ECDHE_RSA_WITH_NULL).*/ regex
	event "WSTG-CRYP-04: Weak cipher suite negotiated - insecure encryption"
}

# =============================================================================
# Additional Input Validation Rules
# =============================================================================

signature ZK-WSTG0746 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(<|%3c)(script|iframe|object|embed|applet|form|input|button|video|audio|svg|marquee|isindex|meta|base|link|style|math|noscript|noembed|noframes|plaintext|xss|details|summary|textarea|title|svg|animate|set|use|handler).*(>|%3e).*/ regex
	event "WSTG-INPV-02: XSS - HTML tag injection attempt"
}

signature ZK-WSTG0747 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*((procedure|function|trigger|view|index|constraint|schema|database|table|column|grant|revoke|commit|rollback|savepoint|lock|unlock)\s*\(.*\)|exec\s*\(|execute\s*\(|sp_.*|xp_.*|0x[0-9a-fA-F]{8,}|char\s*\(|concat\s*\(|group_concat\s*\().*/ regex
	event "WSTG-INPV-01: SQL injection - stored procedure or advanced SQL syntax"
}

signature ZK-WSTG0748 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(=|%3D).*((\.\.\/){3,}|%2e%2e%2f%2e%2e%2f|%252e%252e%252f%252e%252e%252f|\/proc\/self|\/dev\/|\\device\\|\\\\[a-z]+\\|file:\/\/|gopher:\/\/|dict:\/\/|ldap:\/\/|tftp:\/\/).*/ regex
	event "WSTG-INPV-04: Path traversal with deep directory traversal or protocol scheme"
}

signature ZK-WSTG0749 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH|DELETE) \/api\/.*/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*"\$where":.*|.*"\$gt":.*|.*"\$regex":.*|.*"\$ne":.*|.*"\$in":.*/ regex
	event "WSTG-INPV-05: NoSQL injection in JSON API payload"
}

signature ZK-WSTG0750 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\?|%3F).*(redirect=|return=|next=|returnUrl=|return_to=|continue=|dest=|destination=|redir=|redirect_url=|redirect_uri=).*(https?:\/\/|\/\/|%2F%2F)[a-zA-Z0-9.-]*\.(com|net|org|io|xyz|top|click|download|stream|gq|ml|cf|tk|pw).*/ regex
	event "WSTG-INPV-06: Open redirect to suspicious external domain"
}