# =============================================================================
# Zeek Signatures — wstg-10-business-logic
# Total rules: 8
# =============================================================================

signature ZK-WSTG10001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /business-logic|price-manipulation/
	event "Detect_Business_Logic_—_Price_Manipulation"
}

signature ZK-WSTG10002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /business-logic|rate-limit/
	event "Detect_Business_Logic_—_Rate_Limit_Bypass"
}

signature ZK-WSTG10003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /business-logic|workflow-bypass/
	event "Detect_Business_Logic_—_Workflow_Bypass"
}

signature ZK-WSTG10004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /business-logic|negative-amount/
	event "Detect_Business_Logic_—_Negative_Quantity_or_Am"
}

signature ZK-WSTG10005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /error-handling|information-disclosure/
	event "Detect_Error_Handling_—_Verbose_Error_Informati"
}

signature ZK-WSTG10006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /cryptography|weak-hash/
	event "Detect_Cryptography_—_Weak_Hash_Algorithm_Usage"
}

signature ZK-WSTG10007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-protection|pii-logging/
	event "Detect_Data_Classification_—_PII_in_Logs"
}

signature ZK-WSTG10008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-protection|encryption-at-rest/
	event "Detect_Data_Classification_—_Unencrypted_Data_a"
}
