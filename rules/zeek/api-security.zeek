# =============================================================================
# Zeek Signatures — api-security
# Total rules: 16
# =============================================================================

signature ZK-API001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bola|idor/
	event "Detect_API1:_Broken_Object_Level_Authorization_"
}

signature ZK-API002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|default-credentials/
	event "Detect_API2:_Broken_Authentication_—_Default_Cr"
}

signature ZK-API003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /bopla|property-level/
	event "Detect_API3:_Broken_Object_Property_Level_Autho"
}

signature ZK-API004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rate-limiting|resource-consumption/
	event "Detect_API4:_Unrestricted_Resource_Consumption_"
}

signature ZK-API005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /flba|privilege-escalation/
	event "Detect_API5:_Broken_Function_Level_Authorizatio"
}

signature ZK-API006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /business-flows|automation/
	event "Detect_API6:_Unrestricted_Access_to_Sensitive_B"
}

signature ZK-API007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ssrf|server-side/
	event "Detect_API7:_Server-Side_Request_Forgery_via_AP"
}

signature ZK-API008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /misconfiguration|swagger/
	event "Detect_API8:_Security_Misconfiguration_—_Expose"
}

signature ZK-API009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /shadow-api|inventory/
	event "Detect_API9:_Improper_Inventory_Management_—_Sh"
}

signature ZK-API010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /unsafe-consumption|response-handling/
	event "Detect_API10:_Unsafe_Consumption_of_API_Respons"
}

signature ZK-API011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /mass-assignment|parameter-tampering/
	event "Detect_API_—_Mass_Assignment_via_Parameter_Tamp"
}

signature ZK-API012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /graphql|dos/
	event "Detect_API_—_GraphQL_Query_Depth_Attack"
}

signature ZK-API013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /jwt|algorithm-none/
	event "Detect_API_—_JWT_Token_None_Algorithm_Attack"
}

signature ZK-API014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-exposure|pii/
	event "Detect_API_—_Excessive_Data_Exposure_in_Respons"
}

signature ZK-API015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /nosql-injection|injection/
	event "Detect_API_—_NoSQL_Injection_in_Request_Paramet"
}

signature ZK-API016 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /api-keys|access-control/
	event "Detect_API_—_Broken_Access_Control_on_API_Keys"
}
