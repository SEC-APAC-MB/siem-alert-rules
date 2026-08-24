# =============================================================================
# Zeek Signatures — WSTG 01-03 (Information Gathering, Configuration, Identity)
# Total rules: 42
# MITRE ATT&CK: T1592, T1595, T1083, T1190, T1078, T1110, T1548
# Compliance: PCI-DSS 6.5, GDPR 32, HIPAA 164.312, NIST SI-4
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software
@load base/protocols/dns/main

# =============================================================================
# WSTG-INFO-01: Search Engine Discovery
# =============================================================================

signature ZK-WSTG0101 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(admin|\.git|\.env|backup|config|\.DS_Store|\.svn|\.htaccess|wp-admin|phpmyadmin|server-status|\.well-known)/ regex
	event "WSTG-INFO-01: Sensitive path accessed - possible search engine discovery"
}

signature ZK-WSTG0102 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(robots\.txt|sitemap\.xml|\.env|web\.config|appsettings\.json)/ regex
	http-header /User-Agent:.*(Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|AhrefsBot|SemrushBot)/ regex
	event "WSTG-INFO-01: Search engine crawler accessing sensitive files"
}

signature ZK-WSTG0103 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(swagger-ui|api-docs|openapi\.json|graphql\?introspection|\.graphql)/ regex
	event "WSTG-INFO-01: API documentation endpoint exposed to crawlers"
}

signature ZK-WSTG0104 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(wp-content|wp-includes|wp-config\.php|xmlrpc\.php|wp-login\.php)/ regex
	http-header /User-Agent:.*(Googlebot|Bingbot|Slurp)/ regex
	event "WSTG-INFO-01: WordPress admin paths indexed by search engines"
}

# =============================================================================
# WSTG-INFO-02: Web Server Fingerprinting
# =============================================================================

signature ZK-WSTG0105 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Server:.*(Apache\/[0-9]|nginx\/[0-9]|Microsoft-IIS\/[0-9]|lighttpd\/[0-9]|OpenSSL\/[0-9]|PHP\/[0-9])/ regex
	event "WSTG-INFO-02: Web server version disclosure in HTTP headers"
}

signature ZK-WSTG0106 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /X-Powered-By:.*(ASP\.NET|PHP\/[0-9]|Express|Next\.js|Django|Rails|Spring)/ regex
	event "WSTG-INFO-02: Technology stack disclosure via X-Powered-By header"
}

signature ZK-WSTG0107 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /403 Forbidden.*Apache|404 Not Found.*nginx|404.*IIS/ regex
	event "WSTG-INFO-02: Server software identified via error page signatures"
}

signature ZK-WSTG0108 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /OPTIONS \// regex
	http-header /Allow:.*(PUT|DELETE|TRACE|TRACK|CONNECT|PATCH)/ regex
	event "WSTG-INFO-02: Verbose OPTIONS response revealing supported HTTP methods"
}

# =============================================================================
# WSTG-INFO-03: Application Architecture Fingerprinting
# =============================================================================

signature ZK-WSTG0109 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie:.*(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|django_language|flask_session|laravel_session|connect\.sid)/ regex
	event "WSTG-INFO-03: Application framework identified via session cookie names"
}

signature ZK-WSTG0110 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(wp-content|wp-includes|wp-admin|Drupal|sites\/default|joomla|bitrix|Magento|Shopify)/ regex
	event "WSTG-INFO-03: CMS framework identified via URL patterns"
}

signature ZK-WSTG0111 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /X-AspNet-Version|X-AspNetMvc-Version|X-Generator:.*Drupal|X-Drupal-Cache/ regex
	event "WSTG-INFO-03: Framework version disclosed via custom HTTP headers"
}

# =============================================================================
# WSTG-INFO-04: Directory Listing
# =============================================================================

signature ZK-WSTG0112 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /Index of \/|Directory listing for \/|Parent Directory|\<title\>Index of/ regex
	event "WSTG-INFO-04: Directory listing enabled - file structure exposed"
}

signature ZK-WSTG0113 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /403 Forbidden/ regex
	http-header /Content-Type: text\/html/ regex
	payload /Index of|Directory listing|Parent Directory/ regex
	event "WSTG-INFO-04: Misconfigured directory listing returning 403 with content"
}

# =============================================================================
# WSTG-INFO-05: Metadata and Source Code Exposure
# =============================================================================

signature ZK-WSTG0114 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(\.git|\.svn|\.hg|\.bzr|CVS|\.DS_Store|Thumbs\.db|desktop\.ini)/ regex
	event "WSTG-INFO-05: Version control or metadata files accessible"
}

signature ZK-WSTG0115 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(package\.json|composer\.json|Gemfile|requirements\.txt|Pipfile|pom\.xml|build\.gradle|\.csproj)/ regex
	event "WSTG-INFO-05: Dependency configuration files exposed"
}

signature ZK-WSTG0116 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(\.env|config\.php|config\.yml|config\.json|database\.yml|settings\.py|\.config)/ regex
	event "WSTG-INFO-05: Configuration files containing secrets exposed"
}

signature ZK-WSTG0117 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(source|src|app|backup|old|bak|tmp|temp)\// regex
	http-response /200 OK/ regex
	event "WSTG-INFO-05: Source code directories accessible externally"
}

# =============================================================================
# WSTG-INFO-06: Error Message Information Disclosure
# =============================================================================

signature ZK-WSTG0118 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /.*(stack trace|Traceback \(most recent call last\)|Exception Details|Server Error in .* Application|Warning: mysql_|Fatal error:|ORA-\d{5}|PostgreSQL query failed).*/ regex
	event "WSTG-INFO-06: Detailed error message disclosing application internals"
}

signature ZK-WSTG0119 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /.*(SQL syntax.*MySQL|Warning.*mysql_|PostgreSQL query failed|Unclosed quotation mark|Microsoft OLE DB|ORA-\d{5}|SQLSTATE\[).*/ regex
	event "WSTG-INFO-06: Database error message disclosing SQL internals"
}

signature ZK-WSTG0120 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /.*(debug mode|debug mode is on|DEBUG=True|APP_DEBUG=true|config\.debug|stack frames).*/ regex
	event "WSTG-INFO-06: Debug mode information disclosure in error response"
}

# =============================================================================
# WSTG-CONF-01: Application Configuration Management
# =============================================================================

signature ZK-WSTG0121 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /X-Frame-Options/ regex
	http-header /!(X-Frame-Options)/ regex
	event "WSTG-CONF-01: Missing X-Frame-Options header - clickjacking risk"
}

signature ZK-WSTG0122 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Strict-Transport-Security/ regex
	http-header /!(Strict-Transport-Security)/ regex
	event "WSTG-CONF-01: Missing HSTS header - transport security risk"
}

signature ZK-WSTG0123 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Content-Security-Policy/ regex
	http-header /!(Content-Security-Policy)/ regex
	event "WSTG-CONF-01: Missing Content-Security-Policy header - XSS risk"
}

signature ZK-WSTG0124 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /X-Content-Type-Options/ regex
	http-header /!(X-Content-Type-Options)/ regex
	event "WSTG-CONF-01: Missing X-Content-Type-Options header - MIME sniffing risk"
}

signature ZK-WSTG0125 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Access-Control-Allow-Origin: \*/ regex
	event "WSTG-CONF-01: CORS wildcard origin - cross-origin attack risk"
}

signature ZK-WSTG0126 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /Set-Cookie:.*(?!(\bSecure\b))/ regex
	event "WSTG-CONF-01: Cookie without Secure flag set"
}

signature ZK-WSTG0127 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /Set-Cookie:.*(?!(\bHttpOnly\b))/ regex
	event "WSTG-CONF-01: Cookie without HttpOnly flag set"
}

# =============================================================================
# WSTG-CONF-02: CORS Misconfiguration
# =============================================================================

signature ZK-WSTG0128 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Access-Control-Allow-Origin: \*/ regex
	http-header /Access-Control-Allow-Credentials: true/ regex
	event "WSTG-CONF-02: CORS misconfiguration - wildcard origin with credentials allowed"
}

signature ZK-WSTG0129 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /Origin: .*/ regex
	http-header /Access-Control-Allow-Origin: .*/ regex
	event "WSTG-CONF-02: CORS origin reflection detected - potential origin bypass"
}

# =============================================================================
# WSTG-CONF-03: HTTP Methods and HEAD Bypass
# =============================================================================

signature ZK-WSTG0130 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /OPTIONS .*/ regex
	http-header /Allow:.*(PUT|DELETE|TRACE|TRACK|CONNECT|PATCH)/ regex
	event "WSTG-CONF-03: Dangerous HTTP methods enabled - PUT/DELETE/TRACE"
}

signature ZK-WSTG0131 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /TRACE .*/ regex
	event "WSTG-CONF-03: TRACE method enabled - potential XST vulnerability"
}

signature ZK-WSTG0132 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /PUT \/.*\.(php|asp|jsp|py|rb|sh|cgi)/ regex
	event "WSTG-CONF-03: PUT method used to upload executable file"
}

# =============================================================================
# WSTG-CONF-04: Debug Mode and Admin Endpoints
# =============================================================================

signature ZK-WSTG0133 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(debug|test|console|actuator|phpinfo|info\.php|server-info|jmx-console|adminer|_profiler|graphql\?introspection)/ regex
	event "WSTG-CONF-04: Debug/test/admin endpoints accessible"
}

signature ZK-WSTG0134 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(actuator\/env|actuator\/health|actuator\/configprops|actuator\/mappings|actuator\/beans|actuator\/loggers|actuator\/heapdump)/ regex
	event "WSTG-CONF-04: Spring Boot Actuator sensitive endpoints exposed"
}

signature ZK-WSTG0135 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(graphql\?introspection|graphiql|playground)/ regex
	event "WSTG-CONF-04: GraphQL introspection enabled - schema exposed"
}

# =============================================================================
# WSTG-IDNT-01: Default Credentials
# =============================================================================

signature ZK-WSTG0136 {
	ip-proto tcp
	dst-port = { 22 80 443 3389 3306 5432 8080 8443 }
	payload /.*(admin|root|test|guest|default|password|123456|admin123|root123).*/ regex
	http-request /\/(login|auth|signin|wp-login\.php|administrator)/ regex
	event "WSTG-IDNT-01: Default credentials usage attempt detected"
}

signature ZK-WSTG0137 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(admin|administrator|root|superuser|manager|console|cpanel)/ regex
	http-header /Authorization: Basic .*/ regex
	event "WSTG-IDNT-01: Basic auth attempt on admin endpoints - possible default credentials"
}

# =============================================================================
# WSTG-IDNT-02: User Enumeration
# =============================================================================

signature ZK-WSTG0138 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin|authenticate|api\/auth)/ regex
	http-response /.*(invalid username|user not found|email not registered|account does not exist|no account found).*/ regex
	event "WSTG-IDNT-02: User enumeration via different error messages"
}

signature ZK-WSTG0139 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/users|api\/check-user|api\/validate|register\?email=)/ regex
	event "WSTG-IDNT-02: User enumeration via API user validation endpoints"
}

signature ZK-WSTG0140 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin)/ regex
	payload /.*(username|email|user).*/ regex
	event "WSTG-IDNT-02: Brute force login attempt indicating user enumeration"
}

# =============================================================================
# WSTG-IDNT-03: Weak Password Policy
# =============================================================================

signature ZK-WSTG0141 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(register|signup|create-account|password-reset|change-password)/ regex
	http-response /.*(password must be at least [1-3] characters|password too short|minimum.*[1-3]|password policy too weak).*/ regex
	event "WSTG-IDNT-03: Weak password policy detected - insufficient requirements"
}

signature ZK-WSTG0142 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(register|signup|create-account)/ regex
	http-response /200 OK/ regex
	payload /.*(password123|123456|qwerty|letmein|welcome|monkey|dragon).*/ regex
	event "WSTG-IDNT-03: Common weak password accepted during registration"
}

# =============================================================================
# WSTG-IDNT-04: Account Provisioning
# =============================================================================

signature ZK-WSTG0143 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(register|signup|create-account|api\/users)/ regex
	http-response /200 OK|201 Created/ regex
	event "WSTG-IDNT-04: Unverified account provisioning - no email verification"
}

signature ZK-WSTG0144 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/admin\/users|api\/v1\/users|management\/users)/ regex
	http-header /Authorization: .*/ regex
	http-header /Role: (user|member)/ regex
	event "WSTG-IDNT-04: Low-privilege user accessing admin user management endpoints"
}

# =============================================================================
# WSTG-IDNT-05: Privilege Escalation
# =============================================================================

signature ZK-WSTG0145 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/admin|admin|management|dashboard|console|\/role\/|\/permission\/)/ regex
	http-header /Role: (user|member|viewer|guest)/ regex
	event "WSTG-IDNT-05: Low-privilege role accessing admin endpoints - privilege escalation"
}

signature ZK-WSTG0146 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /PUT \/api\/users\/.*\/role/ regex
	http-header /Authorization: .*/ regex
	payload /.*"role"\s*:\s*"(admin|superuser|root|manager)".*/ regex
	event "WSTG-IDNT-05: Role modification attempt via API - privilege escalation"
}

signature ZK-WSTG0147 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/admin\/|admin\/settings|admin\/config|management\/config)/ regex
	http-header /Cookie: .*(session|token|auth).*/ regex
	event "WSTG-IDNT-05: Regular user session accessing admin API endpoints"
}

# =============================================================================
# WSTG-IDNT-06: SSO and Token Issues
# =============================================================================

signature ZK-WSTG0148 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(oauth|saml|callback|auth\/callback|login\/callback)/ regex
	http-header /Authorization: .*/ regex
	payload /.*token=.*&.*token=.*/ regex
	event "WSTG-IDNT-06: Multiple SSO tokens in request - potential token replay"
}

signature ZK-WSTG0149 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(oauth2|openid-connect|saml2|auth\/login)/ regex
	http-header /Location: .*(access_token|id_token|code)=.*/ regex
	payload /.*state=.*&redirect_uri=.*(http|\/\/|%2F%2F).*/ regex
	event "WSTG-IDNT-06: OAuth redirect URI manipulation - open redirect via SSO"
}

signature ZK-WSTG0150 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(saml|sso|auth\/saml|auth\/sso)/ regex
	payload /.*SAMLRequest.*SAMLResponse.*/ regex
	event "WSTG-IDNT-06: SSO token replay detected - duplicate SSO request"
}

# =============================================================================
# Additional Information Gathering Rules
# =============================================================================

signature ZK-WSTG0151 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(\.well-known\/security\.txt|security\.txt|\/\.well-known\/assetlinks\.json)/ regex
	event "WSTG-INFO-01: Security policy files accessible - verify no sensitive data"
}

signature ZK-WSTG0152 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(crossdomain\.xml|clientaccesspolicy\.xml|\.well-known\/cors)/ regex
	event "WSTG-INFO-01: Flash/Silverlight cross-domain policy exposed"
}

signature ZK-WSTG0153 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(favicon\.ico|apple-touch-icon|browserconfig\.xml|manifest\.json)/ regex
	http-header /ETag: .*/ regex
	event "WSTG-INFO-02: Application fingerprint via icon/manifest ETag values"
}

signature ZK-WSTG0154 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(wp-json|wp-json\/wp\/v2|wp-json\/oembed|\/wp-json\/wp\/v2\/users)/ regex
	event "WSTG-INFO-03: WordPress REST API user enumeration endpoint exposed"
}

signature ZK-WSTG0155 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(phpmyadmin|pma|adminer|sqlbuddy|adminer\.php)/ regex
	event "WSTG-INFO-05: Database management tool accessible externally"
}

signature ZK-WSTG0156 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /Server: .*/ regex
	http-header /X-AspNet-Version: .*/ regex
	event "WSTG-INFO-02: ASP.NET version disclosure via X-AspNet-Version header"
}

signature ZK-WSTG0157 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Public-Key-Pins|Expect-CT/ regex
	http-header /!(Public-Key-Pins)/ regex
	event "WSTG-CONF-01: Missing HTTP Public Key Pinning or Expect-CT header"
}

signature ZK-WSTG0158 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(\.well-known\/openid-configuration|\/\.well-known\/jwks\.json|\/\.well-known\/webfinger)/ regex
	event "WSTG-INFO-01: OpenID Connect configuration endpoint publicly accessible"
}

signature ZK-WSTG0159 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(status|healthcheck|health|ping|version|info|metrics|prometheus)/ regex
	event "WSTG-CONF-04: Application status/health endpoints publicly accessible"
}

signature ZK-WSTG0160 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/docs|api\/v2\/docs|swagger\.json|openapi\.yaml|api-docs\.json)/ regex
	event "WSTG-INFO-01: API documentation exposed - Swagger/OpenAPI accessible"
}

signature ZK-WSTG0161 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Referrer-Policy: .*/ regex
	http-header /!(Referrer-Policy)/ regex
	event "WSTG-CONF-01: Missing Referrer-Policy header - potential information leakage"
}

signature ZK-WSTG0162 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Permissions-Policy: .*/ regex
	http-header /!(Permissions-Policy)/ regex
	event "WSTG-CONF-01: Missing Permissions-Policy header - browser features unrestricted"
}