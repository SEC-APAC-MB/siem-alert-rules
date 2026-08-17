# =============================================================================
# Zeek Signatures — mitre-attack
# Total rules: 15
# =============================================================================

signature ZK-MITRET1190 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /initial-access|exploit/
	event "Detect_Exploit_Public-Facing_Application"
}

signature ZK-MITRET1078 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /defense-evasion|valid-accounts/
	event "Detect_Valid_Accounts_Usage"
}

signature ZK-MITRET1110 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /credential-access|brute-force/
	event "Detect_Brute_Force_Authentication"
}

signature ZK-MITRET1059 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /execution|command-scripting/
	event "Detect_Command_and_Scripting_Interpreter"
}

signature ZK-MITRET1486 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /impact|ransomware/
	event "Detect_Data_Encrypted_for_Impact_(Ransomware)"
}

signature ZK-MITRET1566 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /initial-access|phishing/
	event "Detect_Phishing_Link_Click_Detection"
}

signature ZK-MITRET1053 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /persistence|scheduled-task/
	event "Detect_Scheduled_Task/Job_Creation"
}

signature ZK-MITRET1071 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /command-and-control|protocol-abuse/
	event "Detect_Application_Layer_Protocol_Abuse_(C2)"
}

signature ZK-MITRET1562 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /defense-evasion|impair-defenses/
	event "Detect_Impair_Defenses_—_Security_Tool_Disable"
}

signature ZK-MITRET1087 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /discovery|account-discovery/
	event "Detect_Account_Discovery"
}

signature ZK-MITRET1210 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /lateral-movement|remote-exploit/
	event "Detect_Exploitation_of_Remote_Services"
}

signature ZK-MITRET1055 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /defense-evasion|process-injection/
	event "Detect_Process_Injection"
}

signature ZK-MITRET1003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /credential-access|credential-dumping/
	event "Detect_OS_Credential_Dumping"
}

signature ZK-MITRET1046 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /discovery|network-scan/
	event "Detect_Network_Service_Discovery"
}

signature ZK-MITRET1048 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /exfiltration|alternative-protocol/
	event "Detect_Exfiltration_Over_Alternative_Protocol"
}
