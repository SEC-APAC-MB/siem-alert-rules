# =============================================================================
# Zeek Signatures — compliance-pci-dss
# PCI-DSS specific detection rules covering all 12 requirements.
# Total rules: 35
# Reference: PCI-DSS v4.0
# =============================================================================

# --- Requirement 1: Network Security Controls ---

signature ZK-PCI001 {
	ip-proto tcp
	src-ip !$HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r1|firewall-bypass|unauthorized-access/
	event "Detect_PCI-DSS_R1_—_Firewall_Bypass_or_Unauthorized_Network_Access"
	# PCI-DSS Req 1 - Network Security
}

signature ZK-PCI002 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r1|dmz-violation|cardholder-network-exposure/
	event "Detect_PCI-DSS_R1_—_DMZ_Violation_Exposing_Cardholder_Data_Network"
	# PCI-DSS Req 1 - DMZ
}

signature ZK-PCI003 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r1|default-deny|permissive-rule/
	event "Detect_PCI-DSS_R1_—_Permissive_Firewall_Rule_Violating_Default_Deny"
	# PCI-DSS Req 1 - Default Deny
}

# --- Requirement 2: Secure Configurations ---

signature ZK-PCI004 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r2|default-password|vendor-credential/
	event "Detect_PCI-DSS_R2_—_Default_Vendor_Password_Still_in_Use"
	# PCI-DSS Req 2 - Secure Configuration
}

signature ZK-PCI005 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r2|unnecessary-service|running-daemon/
	event "Detect_PCI-DSS_R2_—_Unnecessary_Service_Running_on_Cardholder_System"
	# PCI-DSS Req 2 - Unnecessary Services
}

signature ZK-PCI006 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r2|insecure-configuration|telnet-ftp/
	event "Detect_PCI-DSS_R2_—_Insecure_Protocol_Telnet_FTP_in_CDE"
	# PCI-DSS Req 2 - Insecure Protocols
}

# --- Requirement 3: Protect Stored Account Data ---

signature ZK-PCI007 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r3|cleartext-pan|unencrypted-card-number/
	event "Detect_PCI-DSS_R3_—_Cleartext_PAN_Storage_or_Transmission"
	# PCI-DSS Req 3 - Protect Stored Data
}

signature ZK-PCI008 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r3|weak-encryption|des-rc4/
	event "Detect_PCI-DSS_R3_—_Weak_Encryption_Algorithm_for_Card_Data_DES_RC4"
	# PCI-DSS Req 3 - Weak Crypto
}

signature ZK-PCI009 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r3|key-management|hardcoded-key/
	event "Detect_PCI-DSS_R3_—_Hardcoded_Encryption_Key_for_Cardholder_Data"
	# PCI-DSS Req 3 - Key Management
}

signature ZK-PCI010 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r3|full-pan-display|masking-failure/
	event "Detect_PCI-DSS_R3_—_Full_PAN_Displayed_Instead_of_Masked"
	# PCI-DSS Req 3 - PAN Masking
}

# --- Requirement 4: Protect Data in Transit ---

signature ZK-PCI011 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r4|cleartext-transit|http-card-data/
	event "Detect_PCI-DSS_R4_—_Card_Data_Transmitted_Over_Unencrypted_Channel"
	# PCI-DSS Req 4 - Encryption in Transit
}

signature ZK-PCI012 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r4|weak-tls|sslv3-tls10/
	event "Detect_PCI-DSS_R4_—_Weak_TLS_Version_SSLv3_TLS_1.0_in_Use"
	# PCI-DSS Req 4 - Strong Crypto
}

signature ZK-PCI013 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r4|certificate-expired|invalid-cert/
	event "Detect_PCI-DSS_R4_—_Expired_or_Invalid_TLS_Certificate_for_Card_Data"
	# PCI-DSS Req 4 - Certificate Validity
}

# --- Requirement 5: Malware Protection ---

signature ZK-PCI014 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r5|malware-detection|no-antivirus/
	event "Detect_PCI-DSS_R5_—_Malware_Protection_Disabled_or_Absent_on_CDE_System"
	# PCI-DSS Req 5 - Malware Protection
}

signature ZK-PCI015 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r5|malicious-download|executable-from-internet/
	event "Detect_PCI-DSS_R5_—_Malicious_Executable_Downloaded_on_CDE_System"
	# PCI-DSS Req 5 - Malicious Software
}

# --- Requirement 6: Secure Systems and Software ---

signature ZK-PCI016 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r6|sql-injection|cardholder-application/
	event "Detect_PCI-DSS_R6_—_SQL_Injection_in_Cardholder_Facing_Application"
	# PCI-DSS Req 6 - Secure Development
}

signature ZK-PCI017 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r6|xss|payment-page/
	event "Detect_PCI-DSS_R6_—_Cross_Site_Scripting_on_Payment_Page"
	# PCI-DSS Req 6 - XSS
}

signature ZK-PCI018 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r6|code-injection|web-application-cde/
	event "Detect_PCI-DSS_R6_—_Code_Injection_in_CDE_Web_Application"
	# PCI-DSS Req 6 - Code Injection
}

signature ZK-PCI019 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r6|vulnerability-patching|critical-unpatched/
	event "Detect_PCI-DSS_R6_—_Critical_Vulnerability_Remaining_Unpatched_in_CDE"
	# PCI-DSS Req 6 - Patching
}

# --- Requirement 7: Access Control ---

signature ZK-PCI020 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r7|excessive-privilege|need-to-know-violation/
	event "Detect_PCI-DSS_R7_—_Excessive_Access_Privilege_Violating_Need_to_Know"
	# PCI-DSS Req 7 - Need to Know
}

# --- Requirement 8: Strong Access Controls ---

signature ZK-PCI021 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r8|weak-password|password-policy-violation/
	event "Detect_PCI-DSS_R8_—_Weak_Password_or_Password_Policy_Violation_in_CDE"
	# PCI-DSS Req 8 - Strong Authentication
}

signature ZK-PCI022 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r8|shared-account|generic-login/
	event "Detect_PCI-DSS_R8_—_Shared_or_Generic_Account_Usage_in_CDE"
	# PCI-DSS Req 8 - Unique IDs
}

signature ZK-PCI023 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r8|mfa-bypass|mfa-missing/
	event "Detect_PCI-DSS_R8_—_MFA_Missing_or_Bypassed_for_CDE_Access"
	# PCI-DSS Req 8 - MFA
}

signature ZK-PCI024 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r8|session-timeout|idle-session-active/
	event "Detect_PCI-DSS_R8_—_Session_Timeout_Not_Enforced_in_CDE"
	# PCI-DSS Req 8 - Session Timeout
}

# --- Requirement 9: Physical Access ---

signature ZK-PCI025 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r9|physical-access|unauthorized-entry-cde/
	event "Detect_PCI-DSS_R9_—_Unauthorized_Physical_Access_to_CDE_Systems"
	# PCI-DSS Req 9 - Physical Access
}

# --- Requirement 10: Logging and Monitoring ---

signature ZK-PCI026 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r10|logging-gap|audit-log-disabled/
	event "Detect_PCI-DSS_R10_—_Audit_Logging_Disabled_or_Gap_in_CDE"
	# PCI-DSS Req 10 - Logging
}

signature ZK-PCI027 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r10|log-tampering|log-integrity-failure/
	event "Detect_PCI-DSS_R10_—_Log_Tampering_or_Integrity_Failure_Detected"
	# PCI-DSS Req 10 - Log Integrity
}

signature ZK-PCI028 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r10|review-failure|no-daily-log-review/
	event "Detect_PCI-DSS_R10_—_Daily_Log_Review_Not_Performed_for_CDE_Access"
	# PCI-DSS Req 10 - Daily Review
}

# --- Requirement 11: Security Testing ---

signature ZK-PCI029 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r11|vulnerability-scan|overdue-scan/
	event "Detect_PCI-DSS_R11_—_Overdue_Quarterly_Vulnerability_Scan_for_CDE"
	# PCI-DSS Req 11 - Vulnerability Scanning
}

signature ZK-PCI030 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r11|penetration-test|overdue-annual-test/
	event "Detect_PCI-DSS_R11_—_Overdue_Annual_Penetration_Test_for_CDE"
	# PCI-DSS Req 11 - Penetration Testing
}

signature ZK-PCI031 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r11|intrusion-detection|ids-gap/
	event "Detect_PCI-DSS_R11_—_Intrusion_Detection_Gap_in_CDE_Network"
	# PCI-DSS Req 11 - IDS/IPS
}

# --- Requirement 12: Security Policy ---

signature ZK-PCI032 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|r12|policy-violation|missing-security-policy/
	event "Detect_PCI-DSS_R12_—_Missing_Information_Security_Policy_for_CDE"
	# PCI-DSS Req 12 - Security Policy
}

# --- Card Data Specific Detection ---

signature ZK-PCI033 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|card-number|visa-mastercard-pattern|cleartext/
	event "Detect_PCI-DSS_—_Payment_Card_Number_Visa_Mastercard_in_Cleartext"
	# PCI-DSS - PAN Detection
}

signature ZK-PCI034 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|track-data|magnetic-stripe|cleartext/
	event "Detect_PCI-DSS_—_Magnetic_Stripe_Track_Data_in_Cleartext"
	# PCI-DSS - Track Data
}

signature ZK-PCI035 {
	ip-proto tcp
	src-ip $HOME_NET
	dst-port 80 443 8080 8443
	payload /pci-dss|cvv-cvv2|security-code|cleartext-storage/
	event "Detect_PCI-DSS_—_CVV_CVV2_Security_Code_Storage_in_Cleartext"
	# PCI-DSS - CVV Storage
}