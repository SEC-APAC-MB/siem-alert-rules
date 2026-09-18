# =============================================================================
# Zeek Signatures — wstg-04-06
# Total rules: 20
# =============================================================================

signature ZK-WSTG04001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|cleartext-credentials/
	event "Detect_Credentials_Transmitted_Over_Unencrypted"
}

signature ZK-WSTG04002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|default-credentials/
	event "Detect_Default_Credentials_Usage_on_Login"
}

signature ZK-WSTG04003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|lockout/
	event "Detect_Account_Lockout_Mechanism_Failure"
}

signature ZK-WSTG04004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|auth-bypass/
	event "Detect_Authentication_Schema_Bypass_Attempt"
}

signature ZK-WSTG04005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|remember-me/
	event "Detect_Weak_Remember-Me_Cookie_Detection"
}

signature ZK-WSTG04006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|browser-cache/
	event "Detect_Browser_Cache_Sensitivity_—_Missing_No-C"
}

signature ZK-WSTG04007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|basic-auth/
	event "Detect_Weak_Authentication_—_Basic_Auth_Over_HT"
}

signature ZK-WSTG04008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|mfa/
	event "Detect_MFA_Bypass_or_Absence_for_Privileged_Acc"
}

signature ZK-WSTG04009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|credential-stuffing/
	event "Detect_Credential_Stuffing_Attack_Detected"
}

signature ZK-WSTG04010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|jwt/
	event "Detect_JWT_Algorithm_None_Attack"
}

signature ZK-WSTG04011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authorization|directory-traversal/
	event "Detect_Directory_Traversal_Attack_Detected"
}

signature ZK-WSTG04012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authorization|privilege-escalation/
	event "Detect_Authorization_Schema_Bypass_via_Role_Man"
}

signature ZK-WSTG04013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authorization|idor/
	event "Detect_Insecure_Direct_Object_Reference_(IDOR)"
}

signature ZK-WSTG04014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authorization|oauth/
	event "Detect_OAuth_Token_Scope_Escalation"
}

signature ZK-WSTG04015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /session|csrf/
	event "Detect_Cross-Site_Request_Forgery_(CSRF)"
}

signature ZK-WSTG04016 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /session|session-fixation/
	event "Detect_Session_Fixation_Attack"
}

signature ZK-WSTG04017 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /session|url-token/
	event "Detect_Session_Token_in_URL_Parameters"
}

signature ZK-WSTG04018 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /session|session-hijacking/
	event "Detect_Concurrent_Session_on_Different_IPs"
}

signature ZK-WSTG04019 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /session|jwt/
	event "Detect_JWT_Token_Tampering_or_Forgery"
}

signature ZK-WSTG04020 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /session|cookie/
	event "Detect_Insecure_Session_Cookie_Attributes"
}
