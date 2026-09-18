# =============================================================================
# Zeek Signatures — wstg-01-03
# Total rules: 20
# =============================================================================

signature ZK-WSTG01001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|reconnaissance/
	event "Detect_Search_Engine_Discovery_of_Sensitive_Con"
}

signature ZK-WSTG01002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|fingerprinting/
	event "Detect_Web_Server_Fingerprinting_via_Headers"
}

signature ZK-WSTG01003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|fingerprinting/
	event "Detect_Application_Architecture_Fingerprinting"
}

signature ZK-WSTG01004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|directory-listing/
	event "Detect_Directory_Listing_Exposure"
}

signature ZK-WSTG01005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|metadata/
	event "Detect_Metadata_and_Source_Code_Exposure"
}

signature ZK-WSTG01006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|error-disclosure/
	event "Detect_Error_Message_Information_Disclosure"
}

signature ZK-WSTG01007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|url-exposure/
	event "Detect_Sensitive_Data_in_URL_Parameters"
}

signature ZK-WSTG01008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /configuration|http-methods/
	event "Detect_HTTP_Methods_Allowed_—_Verbose_OPTIONS_R"
}

signature ZK-WSTG01009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /configuration|cors/
	event "Detect_CORS_Wildcard_Origin_Misconfiguration"
}

signature ZK-WSTG01010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /configuration|csp/
	event "Detect_Content_Security_Policy_Missing_or_Weak"
}

signature ZK-WSTG01011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /configuration|security-headers/
	event "Detect_Security_Headers_Missing_(HSTS,_X-Frame-"
}

signature ZK-WSTG01012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|subdomain-takeover/
	event "Detect_Subdomain_Takeover_via_CNAME"
}

signature ZK-WSTG01013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|cloud-enumeration/
	event "Detect_Cloud_Storage_Bucket_Enumeration"
}

signature ZK-WSTG01014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /information-gathering|api-docs/
	event "Detect_API_Documentation_Exposure_(Swagger/Open"
}

signature ZK-WSTG01015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /configuration|debug-mode/
	event "Detect_Debug_Mode_and_Test_Endpoints_Exposed"
}

signature ZK-WSTG01016 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /identity-management|default-credentials/
	event "Detect_Default_Credentials_on_Network_Devices"
}

signature ZK-WSTG01017 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /identity-management|user-enumeration/
	event "Detect_User_Enumeration_via_Login_Error_Message"
}

signature ZK-WSTG01018 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /identity-management|account-provisioning/
	event "Detect_Account_Provisioning_Without_Approval"
}

signature ZK-WSTG01019 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /identity-management|privilege-escalation/
	event "Detect_Privilege_Escalation_via_Role_Assignment"
}

signature ZK-WSTG01020 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /identity-management|sso/
	event "Detect_SSO_Token_Replay_Attack"
}
