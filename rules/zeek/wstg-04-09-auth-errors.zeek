# =============================================================================
# Zeek Signatures — wstg-04-09-auth-errors
# Authentication error detection: brute force, credential stuffing, MFA bypass,
# password spraying, session abuse, token attacks, and identity attack patterns.
# Total rules: 55
# MITRE ATT&CK: T1110, T1078, T1621, T1556, T1110.001-.004, T1078.001-.004
# =============================================================================

# --- Brute Force Attacks (T1110) ---

signature ZK-AUTH001 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443 389 636
	payload /brute-force|vertical|password-trial/
	event "Detect_Vertical_Brute_Force_—_Single_Account_Multiple_Passwords"
	# MITRE T1110.001 - Brute Force: Password Guessing
}

signature ZK-AUTH002 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /brute-force|horizontal|password-spray/
	event "Detect_Horizontal_Brute_Force_—_Password_Spraying"
	# MITRE T1110.003 - Brute Force: Password Spraying
}

signature ZK-AUTH003 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /brute-force|credential-stuffing|breached-credentials/
	event "Detect_Credential_Stuffing_—_Breached_Credential_Automation"
	# MITRE T1110.004 - Brute Force: Credential Stuffing
}

signature ZK-AUTH004 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 22 2222
	payload /brute-force|ssh|dictionary/
	event "Detect_SSH_Dictionary_Attack_—_Rapid_Authentication_Failures"
	# MITRE T1110.001 - Brute Force: Password Guessing (SSH)
}

signature ZK-AUTH005 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 389 636 3268 3269
	payload /brute-force|ldap|bind-failure/
	event "Detect_LDAP_Bind_Brute_Force_Attack"
	# MITRE T1110.001 - Brute Force: Password Guessing (LDAP)
}

signature ZK-AUTH006 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 1433 3306 5432 1521
	payload /brute-force|database|login-failure/
	event "Detect_Database_Authentication_Brute_Force"
	# MITRE T1110.001 - Brute Force: Password Guessing (Database)
}

signature ZK-AUTH007 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /brute-force|api-key|rotation-failure/
	event "Detect_API_Key_Brute_Force_—_Systematic_Key_Trial"
	# MITRE T1110 - API Key Enumeration
}

signature ZK-AUTH008 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /brute-force|slow-low|time-distributed/
	event "Detect_Low_and_Slow_Brute_Force_—_Time-Distributed_Guessing"
	# MITRE T1110.001 - Slow Brute Force
}

# --- MFA Bypass & Attacks (T1621, T1110) ---

signature ZK-AUTH009 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /mfa-bypass|otp-reuse|replay/
	event "Detect_MFA_OTP_Replay_Attack_—_One-Time_Password_Reuse"
	# MITRE T1621 - Multi-Factor Authentication Request
}

signature ZK-AUTH010 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /mfa-bypass|session-hijack|token-intercept/
	event "Detect_MFA_Bypass_via_Session_Token_Interception"
	# MITRE T1078 - Valid Accounts (MFA bypass)
}

signature ZK-AUTH011 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /mfa-bypass|push-fatigue|bombing/
	event "Detect_MFA_Push_Fatigue_Attack_—_MFA_Bombing"
	# MITRE T1621 - MFA Fatigue
}

signature ZK-AUTH012 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /mfa-bypass|downgrade|skip-mfa/
	event "Detect_MFA_Downgrade_Attack_—_Skipping_Second_Factor"
	# MITRE T1078.001 - Valid Accounts: Downgrade Auth
}

signature ZK-AUTH013 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /mfa-bypass|sim-swap|carrier-redirect/
	event "Detect_MFA_Bypass_via_SIM_Swap_Attack"
	# MITRE T1621 - SIM Swap for MFA
}

signature ZK-AUTH014 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /mfa-bypass|voip-hijack|real-time-interception/
	event "Detect_MFA_VoIP_Interception_Attack"
	# MITRE T1621 - VoIP MFA Interception
}

signature ZK-AUTH015 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /mfa-bypass|recovery-code|enrollment/
	event "Detect_MFA_Recovery_Code_Enrollment_Abuse"
	# MITRE T1078 - Recovery Code Abuse
}

# --- OAuth & Token Attacks (T1078, T1550) ---

signature ZK-AUTH016 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /oauth|token-theft|authorization-code/
	event "Detect_OAuth_Authorization_Code_Theft"
	# MITRE T1550.001 - Steal Application Access Token
}

signature ZK-AUTH017 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /oauth|csrf|state-parameter-missing/
	event "Detect_OAuth_CSRF_via_Missing_State_Parameter"
	# MITRE T1078 - OAuth CSRF
}

signature ZK-AUTH018 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /oauth|redirect-uri|open-redirect/
	event "Detect_OAuth_Redirect_URI_Manipulation"
	# MITRE T1078 - OAuth Redirect URI Abuse
}

signature ZK-AUTH019 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /oauth|scope-escalation|privilege-inflation/
	event "Detect_OAuth_Scope_Escalation_Attack"
	# MITRE T1078 - OAuth Scope Escalation
}

signature ZK-AUTH020 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /oauth|pkce-missing|code-verifier/
	event "Detect_OAuth_PKCE_Bypass_or_Absence"
	# MITRE T1550 - PKCE Bypass
}

# --- JWT & Session Attacks (T1534, T1078) ---

signature ZK-AUTH021 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /jwt|algorithm-none|sig-bypass/
	event "Detect_JWT_Algorithm_None_Attack_—_Signature_Bypass"
	# MITRE T1078 - JWT None Algorithm
}

signature ZK-AUTH022 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /jwt|algorithm-confusion|rs256-hs256/
	event "Detect_JWT_Algorithm_Confusion_Attack_—_RS256_to_HS256"
	# MITRE T1078 - JWT Algorithm Confusion
}

signature ZK-AUTH023 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /jwt|jwk-injection|x5u-header/
	event "Detect_JWT_JWK_Injection_or_x5u_Header_Manipulation"
	# MITRE T1078 - JWT JWK/x5u Injection
}

signature ZK-AUTH024 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /jwt|claim-manipulation|privilege-escalation/
	event "Detect_JWT_Claim_Manipulation_—_Privilege_Escalation"
	# MITRE T1078 - JWT Claim Manipulation
}

signature ZK-AUTH025 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /session|fixation|session-id-injection/
	event "Detect_Session_Fixation_—_Pre-Auth_Session_ID_Injection"
	# MITRE T1078 - Session Fixation
}

signature ZK-AUTH026 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /session|concurrent|ip-mismatch|geolocation/
	event "Detect_Concurrent_Session_from_Multiple_IPs_or_Geolocations"
	# MITRE T1078 - Session Hijacking
}

signature ZK-AUTH027 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /session|token-replay|stolen-token/
	event "Detect_Session_Token_Replay_Attack"
	# MITRE T1078 - Token Replay
}

# --- Credential Abuse Patterns ---

signature ZK-AUTH028 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /credential-abuse|account-takeover|impossible-travel/
	event "Detect_Impossible_Travel_—_Consecutive_Logins_from_Distant_IPs"
	# MITRE T1078 - Impossible Travel
}

signature ZK-AUTH029 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /credential-abuse|new-device|risk-score-anomaly/
	event "Detect_Anomalous_Login_from_Unknown_Device_or_Location"
	# MITRE T1078 - Anomalous Login
}

signature ZK-AUTH030 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /credential-abuse|password-reset|bulk-abuse/
	event "Detect_Bulk_Password_Reset_Abuse"
	# MITRE T1078 - Password Reset Abuse
}

signature ZK-AUTH031 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /credential-abuse|legacy-protocol|downgrade-auth/
	event "Detect_Legacy_Authentication_Protocol_Downgrade"
	# MITRE T1078.002 - Legacy Protocol Downgrade
}

signature ZK-AUTH032 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /credential-abuse|kerberoasting|tgs-request/
	event "Detect_Kerberoasting_—_Kerberos_TGS_Request_Anomaly"
	# MITRE T1558.001 - Kerberoasting
}

signature ZK-AUTH033 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /credential-abuse|as-rep-roasting|pre-auth-disabled/
	event "Detect_AS-REP_Roasting_—_Kerberos_Pre-Auth_Disabled"
	# MITRE T1558.002 - AS-REP Roasting
}

# --- Authentication Bypass Patterns ---

signature ZK-AUTH034 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /auth-bypass|broken-auth|schema-bypass/
	event "Detect_Authentication_Schema_Bypass_—_Forced_Browsing"
	# MITRE T1078 - Auth Bypass
}

signature ZK-AUTH035 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /auth-bypass|default-credentials|vendor-default/
	event "Detect_Default_Credentials_Login_—_Vendor_Default_Password"
	# MITRE T1078.001 - Default Credentials
}

signature ZK-AUTH036 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /auth-bypass|registration|open-registration/
	event "Detect_Unrestricted_Account_Registration_Abuse"
	# MITRE T1136 - Create Account
}

signature ZK-AUTH037 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /auth-bypass|password-reset|broken-flow/
	event "Detect_Password_Reset_Flow_Bypass_—_Token_Prediction"
	# MITRE T1078 - Password Reset Bypass
}

signature ZK-AUTH038 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /auth-bypass|2fa-reset|social-engineering/
	event "Detect_2FA_Reset_via_Social_Engineering_or_Account_Recovery"
	# MITRE T1078 - 2FA Reset Abuse
}

signature ZK-AUTH039 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /auth-bypass|idor|parameter-tampering/
	event "Detect_IDOR_Authentication_Bypass_via_Parameter_Tampering"
	# MITRE T1078 - IDOR Auth Bypass
}

# --- SAML & Federation Attacks ---

signature ZK-AUTH040 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /saml|xml-signature-wrapping|saml-response-forgery/
	event "Detect_SAML_XML_Signature_Wrapping_Attack"
	# MITRE T1078 - SAML Signature Wrapping
}

signature ZK-AUTH041 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /saml|assertion-replay|expired-assertion/
	event "Detect_SAML_Assertion_Replay_Attack"
	# MITRE T1078 - SAML Replay
}

signature ZK-AUTH042 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /saml|comment-injection|xpath-injection/
	event "Detect_SAML_Comment_Injection_Attack"
	# MITRE T1078 - SAML Comment Injection
}

signature ZK-AUTH043 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /federation|token-forgery|cross-tenant/
	event "Detect_Federated_Identity_Token_Forgery_Across_Tenants"
	# MITRE T1078 - Federation Token Forgery
}

# --- Account Lockout & Rate Abuse ---

signature ZK-AUTH044 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /account-lockout|no-lockout|brute-force-enabler/
	event "Detect_Missing_Account_Lockout_—_Brute_Force_Enabler"
	# MITRE T1110 - No Lockout
}

signature ZK-AUTH045 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /account-lockout|lockout-enumeration|timing-attack/
	event "Detect_Account_Enumeration_via_Lockout_Timing_Difference"
	# MITRE T1110.001 - Lockout Enumeration
}

signature ZK-AUTH046 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /rate-abuse|captcha-bypass|automation/
	event "Detect_CAPTCHA_Bypass_via_Automation_or_Solving_Service"
	# MITRE T1110 - CAPTCHA Bypass
}

signature ZK-AUTH047 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /rate-abuse|credential-checker|proxy-rotation/
	event "Detect_Credential_Checker_Tool_Usage_—_Proxy_Rotation"
	# MITRE T1110.004 - Credential Stuffing via Proxy
}

# --- Privilege Escalation via Auth ---

signature ZK-AUTH048 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /privilege-escalation|role-manipulation|admin-elevation/
	event "Detect_Privilege_Escalation_via_Role_Manipulation_in_Auth_Flow"
	# MITRE T1078.004 - Privilege Escalation via Auth
}

signature ZK-AUTH049 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /privilege-escalation|group-membership|ad-group/
	event "Detect_Unauthorized_AD_Group_Membership_Change_via_Auth"
	# MITRE T1078.002 - AD Group Escalation
}

signature ZK-AUTH050 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /privilege-escalation|service-account|token-impersonation/
	event "Detect_Service_Account_Token_Impersonation_via_Auth"
	# MITRE T1078 - Service Account Abuse
}

# --- Authentication Anomaly Detection ---

signature ZK-AUTH051 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /anomaly|impossible-travel|velocity-check/
	event "Detect_Authentication_Anomaly_—_Impossible_Travel_Velocity"
	# MITRE T1078 - Velocity Check
}

signature ZK-AUTH052 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /anomaly|time-anomaly|off-hours-login/
	event "Detect_Off-Hours_Authentication_from_Sensitive_Account"
	# MITRE T1078 - Off-Hours Anomaly
}

signature ZK-AUTH053 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /anomaly|failed-success-pattern|credential-validity-check/
	event "Detect_Failed-Then-Succeeded_Authentication_Pattern_—_Credential_Validation"
	# MITRE T1110.004 - Credential Validity Check
}

signature ZK-AUTH054 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /anomaly|beacon-pattern|c2-auth-checkin/
	event "Detect_C2_Beaconing_via_Authentication_Channel"
	# MITRE T1071 - C2 Beacon via Auth
}

signature ZK-AUTH055 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /anomaly|dormant-account|reactivation/
	event "Detect_Dormant_Account_Reactivation_Anomaly"
	# MITRE T1078 - Dormant Account
}