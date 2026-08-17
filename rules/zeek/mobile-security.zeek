# =============================================================================
# Zeek Signatures — Mobile Security
# Total rules: 27
# MITRE ATT&CK: T1552, T1040, T1548, T1190, T1213, T1110, T1078
# Compliance: PCI-DSS 6.5, GDPR 32, HIPAA 164.312, NIST SI-4, IA-2
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# Certificate Pinning Bypass
# =============================================================================

signature ZK-MOBSEC-001 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(login|auth|session|token)/ regex
	http-header /X-Proxy-Connection: .*/ regex
	http-header /Proxy-Authorization: .*/ regex
	event "MOB-SEC-001: Certificate pinning bypass - proxy detected on mobile API"
}

signature ZK-MOBSEC-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /User-Agent: .*(Frida|Objection|SSLKillSwitch|SSLUnpinning|Xposed|Cydia|Substrate|Magisk)/ regex
	event "MOB-SEC-002: Certificate pinning bypass tool detected in user-agent"
}

# =============================================================================
# Insecure Data Storage
# =============================================================================

signature ZK-MOBSEC-003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/(user|profile|account|settings)/ regex
	payload /.*"(password|token|api_key|secret|ssn|credit_card|pin|otp)"\s*:\s*"[^"]*".*/ regex
	http-header /Content-Type: application\/json/ regex
	event "MOB-SEC-003: Sensitive data transmitted in cleartext via mobile API"
}

signature ZK-MOBSEC-004 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*"(password|token|api_key|secret|ssn|credit_card|pin|otp|auth_code)"\s*:\s*"[^"]*".*/ regex
	event "MOB-SEC-004: API response containing sensitive data in cleartext"
}

# =============================================================================
# Rooted/Jailbroken Device Detection
# =============================================================================

signature ZK-MOBSEC-005 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(device|register|check|attest|verify)/ regex
	payload /.*"(rooted|jailbroken|superuser|cydia|substrate|xposed|magisk|frida)"\s*:\s*(true|1|"yes").*/ regex
	event "MOB-SEC-005: Rooted/jailbroken device detected via API"
}

signature ZK-MOBSEC-006 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(device|register|check|attest|verify)/ regex
	payload /.*"(debug_mode|developer_mode|debuggable|test_mode|emulator|simulator)"\s*:\s*(true|1|"yes").*/ regex
	event "MOB-SEC-006: Debug/developer mode detected on mobile device"
}

# =============================================================================
# Insecure Network Communication
# =============================================================================

signature ZK-MOBSEC-007 {
	ip-proto tcp
	dst-port = { 80 }
	http-request /\/api\/v[0-9]+\/(login|auth|session|token|payment|checkout|account|profile)/ regex
	event "MOB-SEC-007: Sensitive API call over unencrypted HTTP"
}

signature ZK-MOBSEC-008 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /X-Mobile-App-Version: .*(debug|dev|test|beta|alpha|canary|nightly).*/ regex
	event "MOB-SEC-008: Mobile app running in debug/development build"
}

# =============================================================================
# Sensitive Data in Logs
# =============================================================================

signature ZK-MOBSEC-009 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(log|analytics|crash|error|debug|trace)/ regex
	payload /.*"(password|token|api_key|secret|ssn|credit_card|pin|otp|auth_code|session_id)".*/ regex
	event "MOB-SEC-009: Sensitive data sent to mobile analytics/logging endpoint"
}

# =============================================================================
# App Tampering
# =============================================================================

signature ZK-MOBSEC-010 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(attest|verify|integrity|check)/ regex
	payload /.*"(signature|hash|checksum|digest)"\s*:\s*"[^"]*".*/ regex
	payload /.*"tampered"\s*:\s*(true|1|"yes").*/ regex
	event "MOB-SEC-010: App tampering detected - signature/hash mismatch"
}

signature ZK-MOBSEC-011 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(device|check|attest|verify)/ regex
	payload /.*"(repackaged|resigned|modified|patched|hooked)"\s*:\s*(true|1|"yes").*/ regex
	event "MOB-SEC-011: App repackaging/re-signing detected"
}

# =============================================================================
# Deep Link Hijacking
# =============================================================================

signature ZK-MOBSEC-012 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(deeplink|link|redirect|callback|open)/ regex
	payload /.*"(url|redirect|next|return|target|destination)"\s*:\s*"(http|https):\/\/[^"]*\?(redirect|next|url|continue|return)=.*(http|javascript|data).*/ regex
	event "MOB-SEC-012: Deep link hijacking - redirect parameter injection"
}

signature ZK-MOBSEC-013 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(deeplink|link|open|navigate)/ regex
	payload /.*"(url|path|uri|scheme)"\s*:\s*"(javascript:|data:|file:|intent:|app:).*/ regex
	event "MOB-SEC-013: Deep link with dangerous scheme - JavaScript/data/FILE URI"
}

# =============================================================================
# Biometric Auth Bypass
# =============================================================================

signature ZK-MOBSEC-014 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(biometric|fingerprint|face|touch|auth)/ regex
	payload /.*"(bypass|fallback|error_override|device_compromised)"\s*:\s*(true|1|"yes").*/ regex
	event "MOB-SEC-014: Biometric authentication bypass attempt detected"
}

signature ZK-MOBSEC-015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/api\/v[0-9]+\/(biometric|fingerprint|face|touch|auth)/ regex
	payload /.*"(fallback|backup|alternative)"\s*:\s*"(password|pin|passcode|pattern)".*/ regex
	event "MOB-SEC-015: Biometric auth fallback to password/PIN - potential bypass"
}

# =============================================================================
# Push Notification Data Leak
# =============================================================================

signature ZK-MOBSEC-016 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/api\/v[0-9]+\/(push|notification|notify|message)/ regex
	payload /.*"(password|pin|otp|token|ssn|credit_card|account_number|balance|auth_code)"\s*:\s*"[^"]*".*/ regex
	event "MOB-SEC-016: Sensitive data in push notification payload"
}

signature ZK-MOBSEC-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/api\/v[0-9]+\/(push|notification|notify|message)/ regex
	payload /.*"(visible|show_preview|display)"\s*:\s*(true|1|"yes").*/ regex
	payload /.*"(password|pin|otp|token|ssn|credit_card|account_number|balance)".*/ regex
	event "MOB-SEC-017: Push notification with sensitive data and visible preview"
}

# =============================================================================
# Hardcoded Secrets
# =============================================================================

signature ZK-MOBSEC-018 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /Authorization: (Basic|Bearer)\s+(admin|root|test|demo|secret|password|api_key|sk_test|pk_test).*/ regex
	event "MOB-SEC-018: Hardcoded/default credentials in mobile API request"
}

signature ZK-MOBSEC-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*/ regex
	http-header /X-API-Key: (test|demo|secret|password|admin|root|sk_test|pk_test|AIza)[a-zA-Z0-9]*/ regex
	event "MOB-SEC-019: Hardcoded API key in mobile request header"
}

# =============================================================================
# WebView Vulnerability
# =============================================================================

signature ZK-MOBSEC-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(webview|browser|navigate|open)/ regex
	payload /.*"(url|uri|path|link)"\s*:\s*"(javascript:|data:text\/html|file:\/\/).*/ regex
	event "MOB-SEC-020: WebView loading dangerous scheme - JavaScript/data/FILE URI"
}

signature ZK-MOBSEC-021 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(webview|browser|navigate|open)/ regex
	payload /.*"(javascript_enabled|js_enabled|allow_javascript)"\s*:\s*(true|1|"yes").*/ regex
	payload /.*"(file_access|allow_file_access)"\s*:\s*(true|1|"yes").*/ regex
	event "MOB-SEC-021: WebView with JavaScript and file access enabled"
}

# =============================================================================
# Mobile Supply Chain
# =============================================================================

signature ZK-MOBSEC-022 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(device|check|attest|verify|integrity)/ regex
	payload /.*"(sdk_version|library_version|third_party)"\s*:\s*"[^"]*".*/ regex
	payload /.*"(vulnerable|outdated|deprecated|critical|known_vulnerability)"\s*:\s*(true|1|"yes").*/ regex
	event "MOB-SEC-022: Vulnerable third-party SDK detected on mobile device"
}

# =============================================================================
# Location Data Exfiltration
# =============================================================================

signature ZK-MOBSEC-023 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(location|geolocation|position|track)/ regex
	payload /.*"(latitude|longitude|accuracy|altitude|speed|bearing)"\s*:\s*[-0-9.]+.*/ regex
	http-header /User-Agent: .*(android|iphone|ipad|mobile)/ regex
	event "MOB-SEC-023: Location data transmitted via mobile API"
}

# =============================================================================
# Clipboard Data Leak
# =============================================================================

signature ZK-MOBSEC-024 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST) \/api\/v[0-9]+\/(clipboard|paste|copy)/ regex
	payload /.*"(content|text|data)"\s*:\s*"[^"]*".*/ regex
	payload /.*"(password|token|credit_card|ssn|otp|pin|auth_code)".*/ regex
	event "MOB-SEC-024: Clipboard data containing sensitive information transmitted"
}

# =============================================================================
# Token Storage Insecure
# =============================================================================

signature ZK-MOBSEC-025 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(token|auth|session|refresh)/ regex
	http-response /200 OK/ regex
	http-header /Set-Cookie: .*(token|session|auth|access_token|refresh_token).*/ regex
	http-header /Set-Cookie: .*(?!(\bHttpOnly\b|\bSecure\b)).*/ regex
	event "MOB-SEC-025: Authentication token stored in insecure cookie - missing HttpOnly/Secure"
}

# =============================================================================
# URL Scheme Hijacking
# =============================================================================

signature ZK-MOBSEC-026 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(deeplink|scheme|url|open|navigate)/ regex
	payload /.*"(scheme|url|uri)"\s*:\s*"[a-z][a-z0-9+.-]*:\/\/[^"]*\?(redirect|next|url|continue|return)=.*(http|javascript|data).*/ regex
	event "MOB-SEC-026: URL scheme with redirect parameter - potential hijacking"
}

signature ZK-MOBSEC-027 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/(device|register|check)/ regex
	payload /.*"(keyboard_type|input_method|ime)"\s*:\s*"(third_party|custom|unknown)".*/ regex
	payload /.*"(input_type|field_type)"\s*:\s*"(password|credit_card|ssn|pin|otp)".*/ regex
	event "MOB-SEC-027: Third-party keyboard accessing sensitive input field"
}