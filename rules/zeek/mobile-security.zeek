# =============================================================================
# Zeek Signatures — mobile-security
# Total rules: 10
# =============================================================================

signature ZK-MOB001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /data-storage|masvs/
	event "Detect_Mobile_—_Insecure_Data_Storage_on_Device"
}

signature ZK-MOB002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /network|masvs/
	event "Detect_Mobile_—_Insecure_Network_Communication"
}

signature ZK-MOB003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authentication|hardcoded/
	event "Detect_Mobile_—_Hardcoded_Credentials_in_Binary"
}

signature ZK-MOB004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /authorization|root-detection/
	event "Detect_Mobile_—_Local_Privilege_Escalation_(Roo"
}

signature ZK-MOB005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /intent-spoofing|deep-link/
	event "Detect_Mobile_—_Intent_Spoofing_and_Deep_Link_A"
}

signature ZK-MOB006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /certificate-pinning|ssl/
	event "Detect_Mobile_—_Certificate_Pinning_Bypass"
}

signature ZK-MOB007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /logging|data-exposure/
	event "Detect_Mobile_—_Sensitive_Data_in_Logs"
}

signature ZK-MOB008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /clipboard|data-exposure/
	event "Detect_Mobile_—_Clipboard_Data_Exposure"
}

signature ZK-MOB009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /biometric|auth-bypass/
	event "Detect_Mobile_—_Biometric_Authentication_Bypass"
}

signature ZK-MOB010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /screen-capture|data-theft/
	event "Detect_Mobile_—_Screenshot_and_Screen_Recording"
}
