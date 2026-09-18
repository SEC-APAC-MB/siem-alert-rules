# =============================================================================
# Zeek Signatures — lateral-movement
# Total rules: 10
# =============================================================================

signature ZK-LM001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pass-the-hash|windows/
	event "Detect_Pass-the-Hash_Detection"
}

signature ZK-LM002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pass-the-ticket|kerberos/
	event "Detect_Pass-the-Ticket_(Kerberos)"
}

signature ZK-LM003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /rdp|remote-desktop/
	event "Detect_RDP_Anomalous_Connection"
}

signature ZK-LM004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /ssh|remote-access/
	event "Detect_SSH_Lateral_Movement"
}

signature ZK-LM005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /wmi|psexec/
	event "Detect_WMI/PSExec_Remote_Execution"
}

signature ZK-LM006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /smb|admin-shares/
	event "Detect_SMB_Lateral_Movement_via_Admin_Shares"
}

signature ZK-LM007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /dcom|distributed-com/
	event "Detect_DCOM_Lateral_Movement"
}

signature ZK-LM008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /winrm|remote-shell/
	event "Detect_WinRM_Remote_Shell_Access"
}

signature ZK-LM009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /golden-ticket|kerberos/
	event "Detect_Golden_Ticket_Attack_(Kerberos)"
}

signature ZK-LM010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /silver-ticket|kerberos/
	event "Detect_Silver_Ticket_Attack_(Kerberos)"
}
