# =============================================================================
# Zeek Signatures — wstg-07-09
# Total rules: 32
# =============================================================================

signature ZK-WSTG07001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|sql-injection/
	event "Detect_SQL_Injection_Attack_Detected"
}

signature ZK-WSTG07002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|xss/
	event "Detect_Cross-Site_Scripting_(XSS)_Reflected"
}

signature ZK-WSTG07003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|xss/
	event "Detect_Cross-Site_Scripting_(XSS)_Stored"
}

signature ZK-WSTG07004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|command-injection/
	event "Detect_Command_Injection_Detection"
}

signature ZK-WSTG07005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|ldap-injection/
	event "Detect_LDAP_Injection_Attack"
}

signature ZK-WSTG07006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|xxe/
	event "Detect_XML_External_Entity_(XXE)_Injection"
}

signature ZK-WSTG07007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|ssrf/
	event "Detect_Server-Side_Request_Forgery_(SSRF)"
}

signature ZK-WSTG07008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|ssti/
	event "Detect_Server-Side_Template_Injection_(SSTI)"
}

signature ZK-WSTG07009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|nosql-injection/
	event "Detect_NoSQL_Injection_Attack"
}

signature ZK-WSTG07010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|deserialization/
	event "Detect_Insecure_Deserialization_Attack"
}

signature ZK-WSTG07011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|hpp/
	event "Detect_HTTP_Parameter_Pollution"
}

signature ZK-WSTG07012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|file-upload/
	event "Detect_File_Upload_Attack_—_Malicious_File_Type"
}

signature ZK-WSTG07013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|host-header/
	event "Detect_Host_Header_Injection"
}

signature ZK-WSTG07014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|graphql/
	event "Detect_GraphQL_Injection_and_Introspection_Abus"
}

signature ZK-WSTG07015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /input-validation|buffer-overflow/
	event "Detect_Buffer_Overflow_via_HTTP_Request"
}

signature ZK-WSTG08001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /client-side|dom-xss/
	event "Detect_DOM-Based_Cross-Site_Scripting"
}

signature ZK-WSTG08002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /client-side|js-execution/
	event "Detect_JavaScript_Execution_via_eval_or_documen"
}

signature ZK-WSTG08003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /client-side|open-redirect/
	event "Detect_Client-Side_URL_Redirect_(Open_Redirect)"
}

signature ZK-WSTG08004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /client-side|css-injection/
	event "Detect_CSS_Injection_via_Style_Attribute"
}

signature ZK-WSTG08005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /client-side|postmessage/
	event "Detect_PostMessage_API_Abuse_—_Wildcard_Origin"
}

signature ZK-WSTG08006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /client-side|web-storage/
	event "Detect_Web_Storage_(localStorage/sessionStorage"
}

signature ZK-WSTG08007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /client-side|service-worker/
	event "Detect_Service_Worker_Registration_Abuse"
}

signature ZK-WSTG08008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /client-side|cors/
	event "Detect_CORS_Wildcard_Configuration"
}

signature ZK-WSTG09001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /server-side|ssrf/
	event "Detect_SSRF_to_Internal_Services_and_Cloud_Meta"
}

signature ZK-WSTG09002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /server-side|request-smuggling/
	event "Detect_HTTP_Request_Smuggling"
}

signature ZK-WSTG09003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /server-side|race-condition/
	event "Detect_Race_Condition_—_Concurrent_Request_Expl"
}

signature ZK-WSTG09004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /server-side|file-inclusion/
	event "Detect_File_Inclusion_(LFI/RFI)"
}

signature ZK-WSTG09005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /server-side|code-injection/
	event "Detect_Server-Side_Code_Injection"
}

signature ZK-WSTG09006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /server-side|dos/
	event "Detect_Denial_of_Service_via_Resource_Exhaustio"
}

signature ZK-WSTG09007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /server-side|file-upload/
	event "Detect_Unsafe_File_Upload_—_Webshell"
}

signature ZK-WSTG09008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /cryptography|weak-tls/
	event "Detect_Cryptography_—_Weak_TLS_Cipher_Suite"
}

signature ZK-WSTG09009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /cryptography|hardcoded-keys/
	event "Detect_Cryptography_—_Hardcoded_Encryption_Keys"
}
