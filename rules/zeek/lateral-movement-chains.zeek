# =============================================================================
# Zeek Signatures — lateral-movement-chains
# Multi-stage lateral movement detection: pass-the-hash, pass-the-ticket,
# RDP/SMB/SSH chaining, DCOM exploitation, living-off-the-land, and more.
# Total rules: 35
# MITRE ATT&CK: T1021, T1550, T1563, T1570, T1080, T1047, T1053, T1059
# =============================================================================

# --- Pass-the-Hash & Credential Replay (T1550.002) ---

signature ZK-LMC001 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445 139
	payload /pass-the-hash|ntlm-replay|overpass-the-hash/
	event "Detect_Lateral_Chain_—_Pass-the-Hash_NTLM_Authentication_Replay"
	# MITRE T1550.002 - Pass the Hash
}

signature ZK-LMC002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445 139
	payload /pass-the-hash|overpass-the-hash|kerberos-ntlm/
	event "Detect_Lateral_Chain_—_Overpass-the-Hash_Kerberos_TGT_Request"
	# MITRE T1550.002 - Overpass-the-Hash
}

signature ZK-LMC003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 88
	payload /pass-the-ticket|kerberos|service-ticket/
	event "Detect_Lateral_Chain_—_Pass-the-Ticket_Kerberos_Service_Ticket_Reuse"
	# MITRE T1550.003 - Pass the Ticket
}

signature ZK-LMC004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445 139
	payload /ntlm-relay|smb-relay|challenge-response/
	event "Detect_Lateral_Chain_—_NTLM_Relay_Attack_SMB_Challenge_Response"
	# MITRE T1557 - NTLM Relay
}

# --- RDP Exploitation Chains (T1021.001) ---

signature ZK-LMC005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 3389
	payload /rdp|lateral-movement|anomalous-connection/
	event "Detect_Lateral_Chain_—_RDP_Anomalous_Lateral_Connection_to_Multiple_Hosts"
	# MITRE T1021.001 - RDP
}

signature ZK-LMC006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 3389
	payload /rdp|credential-dumping|restricted-admin/
	event "Detect_Lateral_Chain_—_RDP_Restricted_Admin_Mode_Credential_Exposure"
	# MITRE T1021.001 - RDP Cred Exposure
}

signature ZK-LMC007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 3389
	payload /rdp|session-hijack|shadow-session/
	event "Detect_Lateral_Chain_—_RDP_Session_Hijacking_via_Shadow_Session"
	# MITRE T1021.001 - RDP Hijack
}

# --- SMB & Admin Share Chains (T1021.002) ---

signature ZK-LMC008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445
	payload /smb|admin-share|c-dollar|ipc-dollar/
	event "Detect_Lateral_Chain_—_SMB_Admin_Share_Access_C$_IPC$_Chain"
	# MITRE T1021.002 - SMB Admin Shares
}

signature ZK-LMC009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445
	payload /smb|service-creation|lateral-execution/
	event "Detect_Lateral_Chain_—_SMB_Remote_Service_Creation_for_Execution"
	# MITRE T1021.002 - SMB Remote Service
}

signature ZK-LMC010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445
	payload /smb|scheduled-task|remote-creation/
	event "Detect_Lateral_Chain_—_SMB_Remote_Scheduled_Task_Creation"
	# MITRE T1053.005 - Remote Scheduled Task
}

# --- WMI & PowerShell Remoting (T1047, T1059.001) ---

signature ZK-LMC011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 135 5985 5986
	payload /wmi|lateral-movement|remote-execution/
	event "Detect_Lateral_Chain_—_WMI_Remote_Execution_via_DCERPC"
	# MITRE T1047 - WMI
}

signature ZK-LMC012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 5985 5986
	payload /winrm|powershell-remoting|enter-pssession/
	event "Detect_Lateral_Chain_—_WinRM_PowerShell_Remoting_Lateral_Movement"
	# MITRE T1059.001 - PowerShell Remoting
}

signature ZK-LMC013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 135
	payload /dcom|lateral-movement|com-object-activation/
	event "Detect_Lateral_Chain_—_DCOM_Remote_Object_Activation_Lateral_Movement"
	# MITRE T1021.003 - DCOM
}

# --- SSH Lateral Movement (T1021.004) ---

signature ZK-LMC014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 22 2222
	payload /ssh|lateral-movement|pivot-chain/
	event "Detect_Lateral_Chain_—_SSH_Pivot_Chain_Multiple_Hop_Connections"
	# MITRE T1021.004 - SSH
}

signature ZK-LMC015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 22 2222
	payload /ssh|agent-forwarding|key-reuse/
	event "Detect_Lateral_Chain_—_SSH_Agent_Forwarding_Key_Reuse_Lateral_Movement"
	# MITRE T1021.004 - SSH Agent Forwarding
}

signature ZK-LMC016 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 22 2222
	payload /ssh|proxy-command|tunneling/
	event "Detect_Lateral_Chain_—_SSH_ProxyCommand_Tunneling_Lateral_Movement"
	# MITRE T1570 - SSH Tunneling
}

# --- Kerberos-Based Chains (T1558, T1550) ---

signature ZK-LMC017 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 88
	payload /kerberos|golden-ticket|domain-controller/
	event "Detect_Lateral_Chain_—_Kerberos_Golden_Ticket_Domain_Escalation"
	# MITRE T1558.001 - Golden Ticket
}

signature ZK-LMC018 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 88
	payload /kerberos|silver-ticket|service-ticket-forgery/
	event "Detect_Lateral_Chain_—_Kerberos_Silver_Ticket_Service_Access"
	# MITRE T1558.002 - Silver Ticket
}

signature ZK-LMC019 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 88
	payload /kerberos|as-rep-roasting|pre-auth-disabled/
	event "Detect_Lateral_Chain_—_Kerberos_AS-REP_Roasting_for_Credential_Access"
	# MITRE T1558.002 - AS-REP Roasting
}

signature ZK-LMC020 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 88
	payload /kerberos|delegation|constrained-unconstrained/
	event "Detect_Lateral_Chain_—_Kerberos_Delegation_Chain_Lateral_Movement"
	# MITRE T1558 - Kerberos Delegation
}

# --- Living Off the Land (T1059, T1047, T1218) ---

signature ZK-LMC021 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /lolbin|powershell|encoded-command|download-cradle/
	event "Detect_Lateral_Chain_—_PowerShell_Encoded_Command_Download_Cradle"
	# MITRE T1059.001 - PowerShell LOLBin
}

signature ZK-LMC022 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /lolbin|wmic|remote-execution|process-call/
	event "Detect_Lateral_Chain_—_WMIC_Remote_Process_Execution_Lateral_Movement"
	# MITRE T1047 - WMIC
}

signature ZK-LMC023 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /lolbin|rundll32|remote-load|sideloading/
	event "Detect_Lateral_Chain_—_Rundll32_Remote_DLL_Loading_Lateral_Movement"
	# MITRE T1218.011 - Rundll32
}

signature ZK-LMC024 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /lolbin|mshta|hta-remote|script-execution/
	event "Detect_Lateral_Chain_—_MSHTA_Remote_HTA_Script_Execution_Lateral"
	# MITRE T1218.005 - MSHTA
}

signature ZK-LMC025 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /lolbin|certutil|download-encode|file-transfer/
	event "Detect_Lateral_Chain_—_Certutil_File_Download_and_Encoding_Lateral"
	# MITRE T1218.006 - Certutil
}

# --- Multi-Stage Chain Detection ---

signature ZK-LMC026 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445 3389 135 22
	payload /lateral-chain|reconnaissance-to-exploitation|multi-host/
	event "Detect_Lateral_Chain_—_Multi_Host_Reconnaissance_to_Exploitation_Sequence"
	# MITRE T1046+T1021 - Recon to Exploit Chain
}

signature ZK-LMC027 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445 3389 5985
	payload /lateral-chain|credential-dumping-to-lateral|mimikatz-smb/
	event "Detect_Lateral_Chain_—_Credential_Dumping_Followed_by_SMB_Lateral_Movement"
	# MITRE T1003+T1021.002 - Cred Dump to SMB
}

signature ZK-LMC028 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /lateral-chain|c2-to-lateral|beacon-pivot/
	event "Detect_Lateral_Chain_—_C2_Beacon_to_Internal_Pivot_Movement"
	# MITRE T1071+T1021 - C2 to Lateral
}

signature ZK-LMC029 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 445 139 3389
	payload /lateral-chain|smb-to-rdp|double-pivot/
	event "Detect_Lateral_Chain_—_SMB_to_RDP_Double_Pivot_Movement"
	# MITRE T1021.002+T1021.001 - SMB to RDP
}

signature ZK-LMC030 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 22 2222 80 443
	payload /lateral-chain|ssh-to-web|application-pivot/
	event "Detect_Lateral_Chain_—_SSH_to_Web_Application_Pivot_Movement"
	# MITRE T1021.004+T1190 - SSH to Web Pivot
}

# --- Cloud Lateral Movement ---

signature ZK-LMC031 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8443
	payload /cloud-lateral|aws-iam|role-assumption|cross-account/
	event "Detect_Lateral_Chain_—_AWS_IAM_Role_Assumption_Cross_Account_Movement"
	# MITRE T1078.004 - Cloud Role Assumption
}

signature ZK-LMC032 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8443
	payload /cloud-lateral|instance-metadata|ssrf-imds/
	event "Detect_Lateral_Chain_—_Cloud_Instance_Metadata_Service_IMDS_Lateral"
	# MITRE T1552.005 - Cloud IMDS
}

signature ZK-LMC033 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8443
	payload /cloud-lateral|kubernetes|pod-exec|cluster-pivot/
	event "Detect_Lateral_Chain_—_Kubernetes_Pod_Exec_to_Cluster_Pivot"
	# MITRE T1609 - Container Lateral
}

signature ZK-LMC034 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8443
	payload /cloud-lateral|azure-ad|token-exchange|tenant-pivot/
	event "Detect_Lateral_Chain_—_Azure_AD_Token_Exchange_Tenant_Pivot"
	# MITRE T1550.001 - Cloud Token Pivot
}

signature ZK-LMC035 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8443
	payload /cloud-lateral|gcp-service-account|key-escalation|project-pivot/
	event "Detect_Lateral_Chain_—_GCP_Service_Account_Key_Escalation_Project_Pivot"
	# MITRE T1078.004 - GCP Lateral
}