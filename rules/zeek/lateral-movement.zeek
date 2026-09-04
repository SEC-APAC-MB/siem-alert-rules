# =============================================================================
# Zeek Signatures — Lateral Movement
# Total rules: 27
# MITRE ATT&CK: T1021, T1047, T1550, T1078, T1053, T1543, T1112
# Compliance: PCI-DSS 8.1, NIST AC-17, SI-4, IA-5
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# Pass-the-Hash / Pass-the-Ticket
# =============================================================================

signature ZK-LATR-001 {
	ip-proto tcp
	dst-port = { 445 139 }
	payload /.*(NTLM|Negotiate|Kerberos).*/ regex
	event "LATR-001: NTLM/Kerberos authentication on SMB - pass-the-hash risk"
}

signature ZK-LATR-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(api\/v[0-9]+\/)?(login|auth|signin|authenticate)/ regex
	http-header /Authorization: NTLM .*/ regex
	event "LATR-002: NTLM authentication via HTTP - pass-the-hash indicator"
}

signature ZK-LATR-003 {
	ip-proto tcp
	dst-port = { 88 464 }
	payload /.*(AS-REQ|TGS-REQ|AP-REQ).*/ regex
	event "LATR-003: Kerberos authentication - pass-the-ticket indicator"
}

# =============================================================================
# RDP Lateral Movement
# =============================================================================

signature ZK-LATR-004 {
	ip-proto tcp
	dst-port = { 3389 }
	payload /.*Microsoft Terminal Services.*/ regex
	event "LATR-004: RDP connection detected - lateral movement risk"
}

signature ZK-LATR-005 {
	ip-proto tcp
	dst-port = { 3389 }
	payload /.*(CredSSP|NLA|Restricted Admin).*/ regex
	event "LATR-005: RDP connection with Network Level Authentication"
}

signature ZK-LATR-006 {
	ip-proto tcp
	dst-port = { 3389 }
	payload /.*(Login Failed|Access Denied|Authentication failed).*/ regex
	event "LATR-006: RDP authentication failure - brute force or credential stuffing"
}

# =============================================================================
# SMB Lateral Movement
# =============================================================================

signature ZK-LATR-007 {
	ip-proto tcp
	dst-port = { 445 139 }
	payload /.*(IPC\$|ADMIN\$|C\$|D\$).*/ regex
	event "LATR-007: SMB admin share access - potential lateral movement"
}

signature ZK-LATR-008 {
	ip-proto tcp
	dst-port = { 445 139 }
	payload /.*(PSEXEC|PsExec|remcom|remcomsvc|PAExec).*/ regex
	event "LATR-008: PsExec/remcom execution detected - lateral movement tool"
}

signature ZK-LATR-009 {
	ip-proto tcp
	dst-port = { 445 139 }
	payload /.*\b(exec\(|execute\(|cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32).*/ regex
	event "LATR-009: Remote command execution via SMB"
}

# =============================================================================
# WMI Lateral Movement
# =============================================================================

signature ZK-LATR-010 {
	ip-proto tcp
	dst-port = { 135 }
	payload /.*(IEnumWbemClassObject|IWbemServices|IWbemLocator|Win32_Process|Win32_Service|Win32_OperatingSystem).*/ regex
	event "LATR-010: WMI remote connection detected - lateral movement risk"
}

signature ZK-LATR-011 {
	ip-proto tcp
	dst-port = { 135 }
	payload /.*(Win32_Process\.Create|CreateProcess|cmd\.exe|powershell|wscript|cscript|mshta).*/ regex
	event "LATR-011: WMI remote process creation - lateral movement"
}

# =============================================================================
# WinRM / PowerShell Remoting
# =============================================================================

signature ZK-LATR-012 {
	ip-proto tcp
	dst-port = { 5985 5986 }
	payload /.*(wsman|WS-Man|WSMAN).*/ regex
	event "LATR-012: WinRM connection detected - PowerShell remoting"
}

signature ZK-LATR-013 {
	ip-proto tcp
	dst-port = { 5985 5986 }
	payload /.*(Enter-PSSession|Invoke-Command|New-PSSession|Connect-PSSession).*/ regex
	event "LATR-013: PowerShell remoting command - lateral movement"
}

# =============================================================================
# SSH Lateral Movement
# =============================================================================

signature ZK-LATR-014 {
	ip-proto tcp
	dst-port = { 22 }
	payload /.*SSH-2\.0-.*/ regex
	event "LATR-014: SSH connection detected - lateral movement risk"
}

signature ZK-LATR-015 {
	ip-proto tcp
	dst-port = { 22 }
	payload /.*(Failed password|Permission denied|Authentication failed|invalid user).*/ regex
	event "LATR-015: SSH authentication failure - brute force attempt"
}

# =============================================================================
# DCOM Lateral Movement
# =============================================================================

signature ZK-LATR-016 {
	ip-proto tcp
	dst-port = { 135 }
	payload /.*(IUnknown|IDispatch|IClassFactory|IClassActivator|IOleObject|DcomLaunch).*/ regex
	event "LATR-016: DCOM activation detected - lateral movement risk"
}

# =============================================================================
# DNS Lateral Movement / Tunneling
# =============================================================================

signature ZK-LATR-017 {
	ip-proto tcp
	dst-port = { 53 }
	payload /.*[a-zA-Z0-9]{30,}.*\.(com|net|org|info|xyz|top|click|online|site|club).*/ regex
	event "LATR-017: DNS tunneling - suspicious long subdomain query"
}

signature ZK-LATR-018 {
	ip-proto tcp
	dst-port = { 53 }
	payload /.*(TXT|NULL|MX|SRV).*/ regex
	payload /.*[a-zA-Z0-9]{20,}.*/ regex
	event "LATR-018: DNS TXT/NULL query with encoded data - potential tunneling"
}

# =============================================================================
# HTTP Lateral Movement
# =============================================================================

signature ZK-LATR-019 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/api\/v[0-9]+\/(exec|execute|run|command|shell|cmd|powershell|bash)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "LATR-019: Remote command execution via API - lateral movement"
}

signature ZK-LATR-020 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/api\/v[0-9]+\/(ssh|rdp|winrm|wmi|remote|connect|terminal)/ regex
	http-header /Authorization: Bearer .*/ regex
	event "LATR-020: Remote access API endpoint - lateral movement risk"
}

# =============================================================================
# Scheduled Task / Service Lateral Movement
# =============================================================================

signature ZK-LATR-021 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT) \/api\/v[0-9]+\/(scheduled|tasks?|jobs?|cron|timers?)/ regex
	payload /.*"(command|script|program|executable)"\s*:\s*"(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin).*/ regex
	event "LATR-021: Scheduled task creation with suspicious command - lateral movement"
}

signature ZK-LATR-022 {
	ip-proto tcp
	dst-port = { 445 139 }
	payload /.*(schtasks|at\.exe|sc\.exe|net\s+start|net\s+stop|Create\s+Service).*/ regex
	event "LATR-022: Remote service/task creation via SMB - lateral movement"
}

# =============================================================================
# Anomalous Logon Patterns
# =============================================================================

signature ZK-LATR-023 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/api\/v[0-9]+\/(login|auth|signin|authenticate)/ regex
	http-header /X-Forwarded-For: .*/ regex
	payload /.*(admin|root|service|system|operator|manager).*/ regex
	event "LATR-023: Privileged account login from unusual source IP"
}

signature ZK-LATR-024 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/api\/v[0-9]+\/(login|auth|signin|authenticate)/ regex
	http-header /Authorization: Bearer .*/ regex
	http-header /X-Forwarded-For: .*/ regex
	http-header /X-Real-IP: .*/ regex
	event "LATR-024: Multiple proxy headers - IP address manipulation for lateral movement"
}

# =============================================================================
# Registry Modification
# =============================================================================

signature ZK-LATR-025 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/(config|settings|registry|preferences)/ regex
	payload /.*"(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKLM|HKCU|HKCR)\\\\(Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce|SYSTEM\\\\CurrentControlSet\\\\Services).*/ regex
	event "LATR-025: Registry run key modification via API - persistence/lateral movement"
}

# =============================================================================
# Credential Relay
# =============================================================================

signature ZK-LATR-026 {
	ip-proto tcp
	dst-port = { 445 139 135 }
	payload /.*(Negotiate|NTLM|Kerberos).*/ regex
	payload /.*(challenge|response|relay|reflection|pass-the-hash|overpass-the-hash).*/ regex
	event "LATR-026: Authentication relay attempt detected"
}

# =============================================================================
# Beaconing Detection
# =============================================================================

signature ZK-LATR-027 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /POST \/api\/v[0-9]+\/(checkin|poll|heartbeat|beacon|status|report|callback)/ regex
	http-header /User-Agent: .*(python-requests|curl|wget|Go-http|node-fetch|Custom|Unknown)/ regex
	event "LATR-027: Suspicious beaconing endpoint with bot user-agent - C2 lateral movement"
}