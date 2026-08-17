# =============================================================================
# Zeek Signatures — WSTG 04-06 (Authentication, Authorization, Session Management)
# Total rules: 52
# MITRE ATT&CK: T1078, T1110, T1537, T1187, T1550, T1606
# Compliance: PCI-DSS 8.1-8.6, GDPR 32, HIPAA 164.312, NIST IA-2, AC-3
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# WSTG-ATHN-01: Authentication Bypass
# =============================================================================

signature ZK-WSTG0401 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(admin|dashboard|profile|settings|account)\/?(.*)/ regex
	http-header /Authorization: .*/ regex
	http-response /200 OK/ regex
	event "WSTG-ATHN-01: Authentication bypass - accessing protected resource without valid auth"
}

signature ZK-WSTG0402 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(admin|dashboard|management)\/?(.*)/ regex
	http-header /!(Authorization)/ regex
	event "WSTG-ATHN-01: Accessing admin endpoint without Authorization header"
}

signature ZK-WSTG0403 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin|authenticate)/ regex
	payload /.*"(role|isAdmin|privilege|permissions)"\s*:\s*"(admin|superuser|root|manager)".*/ regex
	event "WSTG-ATHN-01: Authentication response containing role escalation parameters"
}

signature ZK-WSTG0404 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin)/ regex
	http-response /302 Found|301 Moved/ regex
	http-header /Set-Cookie: session=.*/ regex
	payload /.*token=.*&user=admin.*/ regex
	event "WSTG-ATHN-01: Authentication bypass via token manipulation in redirect"
}

# =============================================================================
# WSTG-ATHN-02: Default Credentials
# =============================================================================

signature ZK-WSTG0405 {
	ip-proto tcp
	dst-port = { 22 80 443 3389 3306 5432 8080 8443 27017 }
	payload /.*(admin|root|test|guest|user|operator):?(admin|password|1234|12345|default|welcome|qwerty|letmein|master|changeme).*/ regex
	event "WSTG-ATHN-02: Default credentials attempt detected"
}

signature ZK-WSTG0406 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Authorization: Basic .*/ regex
	payload /.*(admin|root|test|guest|default):.*/ regex
	event "WSTG-ATHN-02: Basic auth with default username - credential stuffing risk"
}

signature ZK-WSTG0407 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(login|auth|signin|authenticate)/ regex
	payload /.*(username|user|email)=admin&(password|pass|pwd)=(admin|password|123456|test|welcome).*/ regex
	event "WSTG-ATHN-02: Login attempt with common default credentials"
}

# =============================================================================
# WSTG-ATHN-03: Brute Force
# =============================================================================

signature ZK-WSTG0408 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(login|auth|signin|authenticate)/ regex
	http-response /401 Unauthorized|403 Forbidden/ regex
	event "WSTG-ATHN-03: Failed login attempt - brute force detection"
}

signature ZK-WSTG0409 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin)/ regex
	payload /.*(password|passwd|pwd|pass).*/ regex
	http-response /429 Too Many Requests/ regex
	event "WSTG-ATHN-03: Rate limit triggered on login endpoint - brute force attempt"
}

signature ZK-WSTG0410 {
	ip-proto tcp
	dst-port = { 22 3389 }
	payload /.*(Failed password|Access denied|Login incorrect|Authentication failed).*/ regex
	event "WSTG-ATHN-03: SSH/RDP brute force - multiple failed authentication attempts"
}

# =============================================================================
# WSTG-ATHN-04: Weak Password Policy
# =============================================================================

signature ZK-WSTG0411 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(register|signup|create-account|password-reset|change-password)/ regex
	payload /.*password=.{1,5}.*/ regex
	event "WSTG-ATHN-04: Password with fewer than 6 characters accepted - weak policy"
}

signature ZK-WSTG0412 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(register|signup|create-account)/ regex
	payload /.*(password123|qwerty|letmein|welcome|monkey|dragon|master|admin123).*/ regex
	event "WSTG-ATHN-04: Common weak password accepted during registration"
}

# =============================================================================
# WSTG-ATHN-05: Credential Stuffing
# =============================================================================

signature ZK-WSTG0413 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(login|auth|signin)/ regex
	http-header /User-Agent: .*(python-requests|curl|wget|HTTPie|http\.rb|java\/)/ regex
	event "WSTG-ATHN-05: Automated login attempt - credential stuffing from bot user-agent"
}

signature ZK-WSTG0414 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/(login|auth|signin)/ regex
	http-header /X-Forwarded-For: .*/ regex
	payload /.*(email|username|user)=.*&(password|pwd)=.*/ regex
	event "WSTG-ATHN-05: Credential stuffing attempt with rotating source IPs"
}

# =============================================================================
# WSTG-ATHN-06: MFA Bypass
# =============================================================================

signature ZK-WSTG0415 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(mfa|2fa|otp|verify|challenge)/ regex
	http-response /302 Found|200 OK/ regex
	http-header /!(X-MFA-Verified)/ regex
	event "WSTG-ATHN-06: MFA bypass - authenticated without MFA verification"
}

signature ZK-WSTG0416 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin)/ regex
	http-response /200 OK|302 Found/ regex
	http-header /Set-Cookie: session=.*/ regex
	http-header /!(Set-Cookie: .*mfa_verified)/ regex
	event "WSTG-ATHN-06: Session created without MFA verification cookie"
}

signature ZK-WSTG0417 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(mfa|2fa|otp|verify|challenge)/ regex
	payload /.*(000000|123456|111111|999999|000000).*/ regex
	event "WSTG-ATHN-06: MFA bypass attempt with predictable OTP values"
}

# =============================================================================
# WSTG-ATHN-07: OAuth/SSO Issues
# =============================================================================

signature ZK-WSTG0418 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(oauth|authorize|auth\/callback|login\/callback)/ regex
	payload /.*redirect_uri=.*(http|\/\/%2F%2F)[^#]*$/ regex
	event "WSTG-ATHN-07: OAuth redirect URI manipulation - open redirect vulnerability"
}

signature ZK-WSTG0419 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(oauth|authorize)/ regex
	payload /.*state=(&|state=|&redirect).*/ regex
	event "WSTG-ATHN-07: OAuth state parameter missing or duplicated - CSRF risk"
}

signature ZK-WSTG0420 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(oauth|token|auth\/token)/ regex
	payload /.*grant_type=client_credentials.*client_secret=.*/ regex
	event "WSTG-ATHN-07: OAuth client secret exposed in token request"
}

# =============================================================================
# WSTG-ATHZ-01: Directory Traversal
# =============================================================================

signature ZK-WSTG0421 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f).*/ regex
	event "WSTG-ATHZ-01: Directory traversal attack detected"
}

signature ZK-WSTG0422 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\.\.\/|..\/)(etc\/passwd|etc\/shadow|windows\/system32|boot\.ini|win\.ini).*/ regex
	event "WSTG-ATHZ-01: Directory traversal targeting system files"
}

signature ZK-WSTG0423 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*(\.\.\/|\.\.\\|%2e%2e).*\.(env|git|svn|config|bak|sql|log|conf|ini|yml|yaml|json|xml).*/ regex
	event "WSTG-ATHZ-01: Directory traversal targeting configuration files"
}

# =============================================================================
# WSTG-ATHZ-02: Privilege Escalation
# =============================================================================

signature ZK-WSTG0424 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/admin|api\/admin|management|admin\/users|admin\/settings)\/?(.*)/ regex
	http-header /Authorization: Bearer .*/ regex
	http-header /X-Role: (user|member|viewer|guest)/ regex
	event "WSTG-ATHZ-02: Low-privilege role accessing admin endpoint - privilege escalation"
}

signature ZK-WSTG0425 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /PUT \/api\/users\/.*\/(role|permissions|groups|admin)/ regex
	payload /.*"(role|permissions|groups)"\s*:\s*"(admin|superuser|root|manager)".*/ regex
	event "WSTG-ATHZ-02: Role/permission modification attempt - privilege escalation"
}

signature ZK-WSTG0426 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/users\/\d+\/admin|api\/v1\/users\/\d+\/role|api\/v1\/users\/\d+\/permissions)/ regex
	http-response /200 OK/ regex
	event "WSTG-ATHZ-02: Successful role/permission change via API - potential privilege escalation"
}

signature ZK-WSTG0427 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/admin\/|admin\/console|admin\/dashboard|admin\/config)\/?(.*)/ regex
	http-header /Cookie: .*(role|user_role|isAdmin)=(user|member|viewer|false|0)/ regex
	event "WSTG-ATHZ-02: Non-admin cookie accessing admin endpoint - horizontal privilege escalation"
}

# =============================================================================
# WSTG-ATHZ-03: Insecure Direct Object Reference (IDOR)
# =============================================================================

signature ZK-WSTG0428 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/users\/|api\/v1\/accounts\/|api\/v1\/orders\/|api\/v1\/transactions\/)\d+/ regex
	http-header /Authorization: Bearer .*/ regex
	event "WSTG-ATHZ-03: Sequential IDOR - accessing user resource by numeric ID"
}

signature ZK-WSTG0429 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/users\/|api\/v1\/accounts\/)\d+\/(profile|email|password|settings|transactions)/ regex
	http-response /200 OK/ regex
	event "WSTG-ATHZ-03: IDOR - accessing sensitive user sub-resource by numeric ID"
}

signature ZK-WSTG0430 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/documents\/|api\/v1\/files\/|api\/v1\/records\/)[a-f0-9]{8,}/ regex
	http-response /200 OK/ regex
	event "WSTG-ATHZ-03: IDOR - accessing document/file by predictable UUID"
}

# =============================================================================
# WSTG-ATHZ-04: Missing Function Level Access Control
# =============================================================================

signature ZK-WSTG0431 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(DELETE|PUT|PATCH) \/(api\/v1\/admin|admin\/users|management\/config)\/?(.*)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "WSTG-ATHZ-04: Admin endpoint accessed with DELETE/PUT/PATCH method"
}

signature ZK-WSTG0432 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v1\/admin\/export|api\/v1\/admin\/import|admin\/backup|admin\/database)/ regex
	http-header /Authorization: Bearer .*/ regex
	http-response /200 OK/ regex
	event "WSTG-ATHZ-04: Admin export/import function accessed - missing access control"
}

signature ZK-WSTG0433 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(admin|manager|console|dashboard)\/?(.*)/ regex
	http-header /!(Authorization)/ regex
	http-response /200 OK/ regex
	event "WSTG-ATHZ-04: Admin page accessible without authentication"
}

# =============================================================================
# WSTG-SESS-01: Session Hijacking
# =============================================================================

signature ZK-WSTG0434 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie: .*/ regex
	http-header /Set-Cookie: .*(?!(\bHttpOnly\b)).*/ regex
	event "WSTG-SESS-01: Session cookie without HttpOnly flag - XSS session theft risk"
}

signature ZK-WSTG0435 {
	ip-proto tcp
	dst-port = { 80 8080 }
	http-header /Set-Cookie: .*/ regex
	http-header /Set-Cookie: .*(?!(\bSecure\b)).*/ regex
	event "WSTG-SESS-01: Session cookie without Secure flag on HTTP - session hijacking risk"
}

signature ZK-WSTG0436 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie: .*(sessionid|session_id|PHPSESSID|JSESSIONID|ASP\.NET_SessionId).*/ regex
	http-header /Set-Cookie: .*(?!(\bSameSite\b)).*/ regex
	event "WSTG-SESS-01: Session cookie without SameSite attribute - CSRF risk"
}

# =============================================================================
# WSTG-SESS-02: Session Fixation
# =============================================================================

signature ZK-WSTG0437 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin)/ regex
	http-header /Cookie: .*(sessionid|session_id|PHPSESSID)=.*/ regex
	http-response /200 OK|302 Found/ regex
	http-header /Set-Cookie: .*(sessionid|session_id|PHPSESSID)=.*/ regex
	event "WSTG-SESS-02: Session fixation - session ID not rotated after login"
}

signature ZK-WSTG0438 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(login|auth|signin)/ regex
	payload /.*sessionid=.*&username=.*/ regex
	event "WSTG-SESS-02: Session fixation via URL parameter - session ID in query string"
}

# =============================================================================
# WSTG-SESS-03: Session Timeout
# =============================================================================

signature ZK-WSTG0439 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie: .*(sessionid|session_id|PHPSESSID).*/ regex
	http-header /Set-Cookie: .*Max-Age=(86400|604800|2592000|31536000).*/ regex
	event "WSTG-SESS-03: Excessively long session Max-Age - insufficient session timeout"
}

signature ZK-WSTG0440 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie: .*(sessionid|session_id|PHPSESSID).*/ regex
	http-header /Set-Cookie: .*(?!(Expires|Max-Age)).*/ regex
	event "WSTG-SESS-03: Session cookie without expiration - persistent session risk"
}

# =============================================================================
# WSTG-SESS-04: CSRF
# =============================================================================

signature ZK-WSTG0441 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|DELETE|PATCH) \/(api\/v1\/users|api\/v1\/accounts|api\/v1\/transactions|api\/v1\/payments)\/?(.*)/ regex
	http-header /!(X-CSRF-Token)/ regex
	http-header /Origin: .*/ regex
	event "WSTG-SESS-04: State-changing request without CSRF token"
}

signature ZK-WSTG0442 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|DELETE|PATCH) \/(api|user|account|transaction|payment)\/?(.*)/ regex
	http-header /Cookie: .*/ regex
	http-header /Referer: .*/ regex
	http-header /!(X-Requested-With)/ regex
	event "WSTG-SESS-04: State-changing request without X-Requested-With header - potential CSRF"
}

signature ZK-WSTG0443 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|DELETE|PATCH) .*/ regex
	http-header /Content-Type: (application\/x-www-form-urlencoded|multipart\/form-data)/ regex
	http-header /Origin: https?:\/\/[^\/]+/ regex
	http-header /!(X-CSRF-Token|X-XSRF-Token)/ regex
	event "WSTG-SESS-04: Form submission without CSRF token - cross-site request forgery risk"
}

# =============================================================================
# WSTG-SESS-05: Cookie Security
# =============================================================================

signature ZK-WSTG0444 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie: .*(auth|token|session|jwt|access_token|refresh_token).*/ regex
	http-header /Set-Cookie: .*(?!(\bHttpOnly\b)).*/ regex
	event "WSTG-SESS-05: Authentication cookie without HttpOnly flag"
}

signature ZK-WSTG0445 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie: .*(auth|token|session|jwt|access_token).*/ regex
	http-header /Set-Cookie: .*(?!(\bSecure\b)).*/ regex
	event "WSTG-SESS-05: Authentication cookie without Secure flag"
}

signature ZK-WSTG0446 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Set-Cookie: .*(auth|token|session|jwt|access_token).*/ regex
	http-header /Set-Cookie: .*(Domain=\.[a-z]+\.[a-z]+).*/ regex
	event "WSTG-SESS-05: Authentication cookie with overly broad domain scope"
}

# =============================================================================
# WSTG-SESS-06: JWT Security
# =============================================================================

signature ZK-WSTG0447 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Authorization: Bearer eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/ regex
	http-header /Authorization: Bearer eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\./ regex
	event "WSTG-SESS-06: JWT with none algorithm detected - algorithm confusion attack"
}

signature ZK-WSTG0448 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0/ regex
	event "WSTG-SESS-06: JWT with explicit none algorithm - authentication bypass"
}

signature ZK-WSTG0449 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-header /Authorization: Bearer eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\./ regex
	payload /.*"alg"\s*:\s*"(HS256|HS384|HS512)".*"kid"\s*:\s*"[^"]*".*/ regex
	event "WSTG-SESS-06: JWT with HMAC algorithm - potential key confusion attack"
}

# =============================================================================
# WSTG-SESS-07: Token Leakage
# =============================================================================

signature ZK-WSTG0450 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/.*\?(token|access_token|id_token|auth_token|session)=.*/ regex
	event "WSTG-SESS-07: Authentication token in URL query string - token leakage risk"
}

signature ZK-WSTG0451 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api|auth|oauth|login)\/?(.*)/ regex
	http-header /Referrer: .*(token|access_token|id_token|session)=.*/ regex
	event "WSTG-SESS-07: Authentication token leaked via Referrer header"
}

signature ZK-WSTG0452 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	http-header /Access-Control-Allow-Origin: \*/ regex
	http-header /Access-Control-Allow-Credentials: true/ regex
	payload /.*"(token|session|auth|password|secret)".*/ regex
	event "WSTG-SESS-07: Sensitive data exposed via CORS with credentials - token leakage"
}