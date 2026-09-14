# Oracle SIEM Baseline — Individual Deployable Rules with Suggested Response Actions

**Source:** `baseline-rules.json` v1.0.0 | **149 rules** | **13 domains**
**Generated:** 2026-09-14

All rules share these defaults:
- **Interval:** 5 minutes
- **Threshold:** >3 events triggers alert
- **Action:** ONS (Oracle Notification Service) alert
- **Event source:** `com.oracle.cloud.monitoring` (all), `com.oracle.cloud.audit` (persistence rules)
- **Rule type:** Query-based against OCI Monitoring metrics

---

## Domain 1: Authentication & Initial Access (10 rules)

### OCI-INITIAL_ACCESS-127 — Phishing Link Detection
- **Detects:** Credential harvesting links in email via URL reputation
- **Suggested Response:** Isolate the user's mailbox, block the phishing URL at the email gateway, reset credentials if clicked, notify the user, submit URL to threat intel feeds.

### OCI-INITIAL_ACCESS-128 — Spear-Phishing Attachment
- **Detects:** Malicious attachments exploiting Office, PDF, or LNK
- **Suggested Response:** Quarantine the email, detonate attachment in sandbox, block sender, scan recipient endpoint, reset credentials if execution confirmed.

### OCI-INITIAL_ACCESS-129 — Valid Account Abuse
- **Detects:** Impossible travel, unusual time, or new device logins
- **Suggested Response:** Force MFA re-authentication, disable account temporarily, investigate source IP and device, review recent account activity, reset credentials.

### OCI-INITIAL_ACCESS-130 — Exploit Public-Facing Application
- **Detects:** Exploitation of CVEs in web apps, VPNs, firewalls
- **Suggested Response:** Patch the vulnerable application, block attacker's source IP, check for web shell deployment, review web server logs for data exfiltration, initiate IR if RCE confirmed.

### OCI-INITIAL_ACCESS-131 — Supply Chain Compromise
- **Detects:** Malicious package or compromised update delivery
- **Suggested Response:** Halt all CI/CD pipelines, roll back to last known-good build, quarantine the malicious package, notify affected teams, conduct full dependency audit.

### OCI-INITIAL_ACCESS-132 — VPN Appliance Exploitation
- **Detects:** Attacks on VPN concentrators (Pulse Secure, Fortinet, etc.)
- **Suggested Response:** Patch VPN appliance, block attacker's IP, review VPN session logs, force re-authentication for all active sessions, check for lateral movement from VPN.

### OCI-INITIAL_ACCESS-133 — Trusted Relationship Abuse
- **Detects:** Lateral movement from MSP/consultant/supplier accounts
- **Suggested Response:** Suspend third-party account, review all access by that account in last 30 days, notify the third-party organization, audit all third-party access permissions.

### OCI-INITIAL_ACCESS-134 — Drive-by Compromise
- **Detects:** Exploit kit activity and malicious iframe injection
- **Suggested Response:** Isolate affected endpoint, block exploit kit domain at proxy, scan for downloaded payloads, reimage if compromise confirmed, educate user on safe browsing.

### OCI-INITIAL_ACCESS-135 — External Remote Services Brute Force
- **Detects:** Password spraying against RDP, SSH, VPN, OWA
- **Suggested Response:** Block source IP, enable account lockout policies, enforce MFA, check for successful authentications from same source, reset passwords for targeted accounts.

### OCI-INITIAL_ACCESS-136 — Hardware Additions
- **Detects:** Rogue USB, pineapple WiFi, or hardware implant indicators
- **Suggested Response:** Physically inspect affected workstation, remove rogue device, review network traffic for rogue AP connections, notify physical security if insider threat suspected.

---

## Domain 2: Privilege Escalation (19 rules)

### OCI-PRIVILEGE-ESCALATION-001 — CVE-2026-86060 RouterOS Exploitation
- **Detects:** MikroTik RouterOS improper argument delimiter allowing privilege escalation
- **MITRE:** T1548 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Patch RouterOS to latest stable version, isolate affected router, review firewall policy changes, check for persistent backdoors on the device.

### OCI-PRIVILEGE-ESCALATION-002/004/011/012 — CVE-2026-53362 Kernel Exploitation (4 instances)
- **Detects:** Linux Kernel privilege escalation via IPv6 networking subsystem
- **MITRE:** T1548 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Apply kernel security patches immediately, isolate affected hosts, check for rootkits, review process execution logs for suspicious root-level processes, reboot after patching.

### OCI-PRIVILEGE-ESCALATION-005/007/014/019 — CVE-2015-3246 Libuser Exploitation (4 instances)
- **Detects:** Red Hat libuser race condition allowing /etc/passwd corruption
- **MITRE:** T1498, T1548, T1110, T1078 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Update libuser package, check /etc/passwd integrity, audit for unauthorized user creation, review authentication logs for brute force patterns.

### OCI-PRIVILEGE-ESCALATION-006/008/015/016/020 — CVE-2015-5287 ABRT Exploitation (5 instances)
- **Detects:** Red Hat ABRT symlink attack for privilege escalation
- **MITRE:** T1548 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Remove or update ABRT package, check for symlink attacks in /var/spool/abrt, audit for unauthorized file access, review system logs for crash handler abuse.

### GHADV-1056 — ArcadeDB Privilege Escalation
- **Detects:** ArcadeDB reader role can execute JS scripting for arbitrary host file read
- **MITRE:** T1548
- **Suggested Response:** Upgrade ArcadeDB, restrict JavaScript scripting API access, audit file read operations, review database access logs.

### GHADV-2197 — Strimzi Unrestricted Secrets Access
- **Detects:** Topic operator grants unrestricted access to all Secrets in namespace
- **MITRE:** T1548
- **Suggested Response:** Upgrade Strimzi, restrict Topic operator RBAC, audit all Secret access in affected namespaces, rotate any exposed secrets.

### GHADV-2198 — Strimzi Cross-Namespace Privilege Escalation
- **Detects:** Cross-namespace escalation via Kafka.spec.entityOperator
- **MITRE:** T1548
- **Suggested Response:** Upgrade Strimzi, restrict entityOperator permissions, audit cross-namespace operations, review Kafka cluster configuration.

### GHADV-3084 — Jenkins Job Import Plugin Permission Bypass
- **Detects:** Missing permission check in HTTP endpoint
- **MITRE:** T1548
- **Suggested Response:** Update or remove Jenkins Job Import Plugin, audit Jenkins job imports, review user permissions, check for unauthorized job modifications.

### GHADV-3086 — Jenkins AppSpider Plugin Permission Bypass
- **Detects:** Missing permission check in form validation method
- **MITRE:** T1548
- **Suggested Response:** Update or remove Jenkins AppSpider Plugin, audit form validation endpoint access, review Jenkins audit logs for exploitation.

---

## Domain 3: Lateral Movement (20 rules)

### OCI-LATERAL_MOVEMENT-167 — Pass-the-Hash Detection
- **Detects:** NTLM hash-based authentication without password
- **Suggested Response:** Isolate source machine, reset compromised credentials, enable LSA protection, audit for additional lateral movement, investigate initial compromise vector.

### OCI-LATERAL_MOVEMENT-168 — Pass-the-Ticket Detection
- **Detects:** Kerberos ticket reuse from different source machines
- **Suggested Response:** Isolate both source and target machines, reset affected service account, audit for additional ticket usage, review Kerberos event logs.

### OCI-LATERAL_MOVEMENT-169 — Lateral Movement via PsExec
- **Detects:** PsExec/WMIExec/SmbExec remote service installation
- **Suggested Response:** Block PsExec via AppLocker, isolate source machine, review services created on target machines, investigate attack chain.

### OCI-LATERAL_MOVEMENT-170 — SSH Lateral Movement
- **Detects:** SSH key-based lateral movement patterns
- **Suggested Response:** Rotate SSH keys, review authorized_keys on all hosts, isolate source machine, audit for additional SSH connections.

### OCI-LATERAL_MOVEMENT-171 — RDP Lateral Movement
- **Detects:** Unusual RDP sessions between workstations
- **Suggested Response:** Block RDP between workstations via GPO, isolate both machines, review RDP session logs, check for data exfiltration.

### OCI-LATERAL_MOVEMENT-172 — Kubernetes Pod-to-Pod Lateral Movement
- **Detects:** Unexpected pod-to-pod communication patterns
- **Suggested Response:** Apply NetworkPolicies to restrict pod communication, isolate source pod, review container logs, audit cluster RBAC.

### OCI-LATERAL_MOVEMENT-173 — DCSync Attack
- **Detects:** DCSync replication request from non-DC accounts
- **Suggested Response:** Isolate source machine immediately, reset compromised account, audit AD for additional compromise, restrict DCSync permissions to Domain Controllers only.

### OCI-LATERAL_MOVEMENT-174 — Golden Ticket Attack
- **Detects:** Kerberos TGT usage with abnormal lifetime or PAC
- **Suggested Response:** Reset krbtgt account password twice (12h gap), isolate affected systems, audit for persistent access, review all Kerberos ticket usage.

### OCI-LATERAL_MOVEMENT-175 — Kerberoasting
- **Detects:** Unusual Kerberos TGS-REQ patterns for SPN enumeration
- **Suggested Response:** Identify targeted service accounts, rotate passwords, audit for offline cracking attempts, enforce AES encryption for Kerberos.

### OCI-LATERAL_MOVEMENT-176 — ARP Spoofing Detection
- **Detects:** ARP spoofing/gratuitous ARP for MITM
- **Suggested Response:** Enable dynamic ARP inspection on switches, isolate spoofing source, review network traffic for intercepted data, check for SSL stripping.

### OCI-LAT-0700 through OCI-LAT-0709 — Correlation Chain Rules (10 rules)
- **Detects:** Multi-stage lateral movement chains (RDP→Credential Access, SSH→Privilege Escalation, SMB→File Encryption, WMI→Persistence, PsExec→Discovery, PowerShell→Credential Dumping, WinRM→Defense Evasion, Kerberoasting→Lateral Movement, DCSync Chain, Pass-the-Hash Chain)
- **MITRE:** Various (T1021.x, T1555, T1548, T1486, T1546.003, T1547.001, T1082, T1059.001, T1003.001, T1027, T1558.001, T1021, T1003.006, T1558, T1550.002)
- **Compliance:** NIST-800-53-SI-4, PCI-DSS-10.2, NIS2-Art.15, DORA-Art.8
- **Suggested Response (all chain rules):** Trigger full incident response — isolate all involved hosts, reset all compromised credentials, preserve forensic evidence, investigate full attack chain from initial access to impact, engage IR team. Chain detections indicate active, multi-stage attacks requiring immediate escalation.

---

## Domain 4: Data Exfiltration (10 rules)

### OCI-EXFILTRATION-157 — DNS Tunneling Detection
- **Suggested Response:** Block exfiltration domain at DNS resolver, capture and analyze DNS traffic, identify source process, investigate what data was exfiltrated.

### OCI-EXFILTRATION-158 — Large Data Transfer to Cloud Storage
- **Suggested Response:** Block destination IP/domain, identify source process and user, audit uploaded data, review cloud storage access logs.

### OCI-EXFILTRATION-159 — ICMP Data Exfiltration
- **Suggested Response:** Block ICMP traffic at firewall for non-essential hosts, identify source process, investigate payload content.

### OCI-EXFILTRATION-160 — HTTPS Data Exfiltration
- **Suggested Response:** Block destination service if not business-approved, identify source user and process, review uploaded data, enforce DLP policies.

### OCI-EXFILTRATION-161 — Email Data Exfiltration
- **Suggested Response:** Disable forwarding rules, investigate user account for compromise, review sent emails for sensitive content, reset credentials.

### OCI-EXFILTRATION-162 — Database Bulk Export
- **Suggested Response:** Revoke database user's export permissions, audit what data was exported, check for unauthorized database access, rotate database credentials.

### OCI-EXFILTRATION-163 — Screen Capture Data Theft
- **Suggested Response:** Investigate source process, check for remote desktop tools, review network traffic for outbound image transfers, restrict screen capture software.

### OCI-EXFILTRATION-164 — Steganography Detection
- **Suggested Response:** Quarantine affected image files, identify embedding process, investigate source user, analyze hidden payload.

### OCI-EXFILTRATION-165 — Web Shell Data Exfiltration
- **Suggested Response:** Remove web shell, patch vulnerable web application, audit for data accessed via web shell, check for persistent backdoors.

### OCI-EXFILTRATION-166 — Clipboard Data Theft
- **Suggested Response:** Identify clipboard monitoring process, isolate affected endpoint, check for malware with clipboard logging, restrict clipboard access via DLP.

---

## Domain 5: Persistence (10 rules)

### OCI-PERSISTENCE-147 — Registry Run Key Modification
- **Suggested Response:** Investigate modifying process, revert unauthorized changes, scan for malware, audit all Run key entries.

### OCI-PERSISTENCE-148 — Scheduled Task Persistence
- **Suggested Response:** Review task action and trigger, delete malicious tasks, identify creating process, audit all scheduled tasks.

### OCI-PERSISTENCE-149 — Service Creation for Persistence
- **Suggested Response:** Review service binary path, stop and delete malicious services, investigate creating process, audit all non-standard services.

### OCI-PERSISTENCE-150 — WMI Event Subscription
- **Suggested Response:** Remove WMI subscription, identify binding process, scan for WMI-based persistence, audit WMI repositories.

### OCI-PERSISTENCE-151 — DLL Search Order Hijacking
- **Suggested Response:** Remove planted DLL, identify planting process, verify application integrity, audit DLL loading paths.

### OCI-PERSISTENCE-152 — Browser Extension Persistence
- **Suggested Response:** Remove extension, investigate installation source, check for data exfiltration via extension, enforce extension allowlists.

### OCI-PERSISTENCE-153 — Kubernetes CronJob Persistence
- **Suggested Response:** Delete malicious CronJob, review container image, check for privilege escalation, audit cluster RBAC.

### OCI-PERSISTENCE-154 — Cloud IAM Backdoor
- **Suggested Response:** Remove rogue IAM role/policy, audit all recent IAM changes, rotate credentials, review CloudTrail for unauthorized access.

### OCI-PERSISTENCE-155 — SSH Authorized Key Injection
- **Suggested Response:** Remove unauthorized key, identify injection source, audit all authorized_keys files, rotate SSH credentials.

### OCI-PERSISTENCE-156 — Cron Job Persistence (Linux)
- **Suggested Response:** Remove malicious cron job, identify modifying process, audit all crontab entries, check for rootkit installation.

---

## Domain 6: Ransomware Detection (10 rules)

### OCI-RANSOMWARE-077 — Mass File Encryption Pattern
- **Suggested Response:** Immediately isolate affected host, identify encryption process, stop the process, assess backup availability, activate ransomware IR plan.

### OCI-RANSOMWARE-078 — Shadow Copy Deletion
- **Suggested Response:** Block vssadmin execution, preserve remaining shadow copies, investigate source process, activate IR plan.

### OCI-RANSOMWARE-079 — Ransom Note Creation
- **Suggested Response:** Preserve ransom note for attribution, isolate affected host, check for network propagation, engage law enforcement if appropriate.

### OCI-RANSOMWARE-080 — Volume Shadow Copy Tampering
- **Suggested Response:** Restore VSS configuration, investigate tampering process, check for backup system compromise, ensure offline backups exist.

### OCI-RANSOMWARE-081 — Backup Deletion via Vssadmin
- **Suggested Response:** Block vssadmin/wbadmin execution, verify backup system integrity, restore from offline backups, investigate source process.

### OCI-RANSOMWARE-082 — Ransomware C2 Beacon Pattern
- **Suggested Response:** Block C2 domain/IP at firewall, isolate beaconing host, identify ransomware variant, check for lateral movement.

### OCI-RANSOMWARE-083 — Mimikatz Credential Dumping Pre-Encryption
- **Suggested Response:** Isolate affected host immediately, reset all credentials accessed by Mimikatz, check for lateral movement, preserve memory for forensics.

### OCI-RANSOMWARE-084 — Lateral Movement via PsExec/WMI
- **Suggested Response:** Block SMB and WMI traffic between hosts, isolate affected machines, identify ransomware variant, check for propagation.

### OCI-RANSOMWARE-085 — Scheduled Task Creation for Encryption
- **Suggested Response:** Delete scheduled tasks, identify creating process, check for ransomware binaries, isolate affected hosts.

### OCI-RANSOMWARE-086 — Registry Run Key Persistence for Ransomware
- **Suggested Response:** Remove registry entry, identify ransomware variant, isolate host, check for encryption activity.

---

## Domain 7: Reconnaissance & Scanning (10 rules)

### OCI-RECONNAISSANCE-117 — Active Directory Domain Enumeration
- **Suggested Response:** Audit source account, restrict LDAP query permissions, monitor for follow-on attacks, check for BloodHound data collection.

### OCI-RECONNAISSANCE-118 — Network Service Discovery (Nmap/Masscan)
- **Suggested Response:** Block scanning source IP, review firewall logs for targeted ports, verify all exposed services are patched, check for follow-on exploitation.

### OCI-RECONNAISSANCE-119 — DNS Zone Transfer Attempt
- **Suggested Response:** Block zone transfers from unauthorized hosts, restrict DNS server AXFR to known secondaries only, review what DNS data was exposed.

### OCI-RECONNAISSANCE-120 — Web Technology Fingerprinting
- **Suggested Response:** Block fingerprinting source, verify all web technologies are current, check for follow-on exploitation, review WAF logs.

### OCI-RECONNAISSANCE-121 — Cloud Asset Enumeration
- **Suggested Response:** Block enumeration source, verify bucket ACLs, check for unauthorized access, enforce bucket policies.

### OCI-RECONNAISSANCE-122 — SSL/TLS Certificate Reconnaissance
- **Suggested Response:** Monitor for follow-on attacks against discovered subdomains, verify certificate validity, check for phishing domain registration.

### OCI-RECONNAISSANCE-123 — API Endpoint Discovery
- **Suggested Response:** Rate-limit API, block fuzzing source, verify API authentication on all endpoints, check for data exposure.

### OCI-RECONNAISSANCE-124 — Email Harvesting & Phishing Prep
- **Suggested Response:** Block enumeration source, verify email security gateway settings, check for follow-on phishing, alert users about potential phishing.

### OCI-RECONNAISSANCE-125 — SNMP Community String Brute Force
- **Suggested Response:** Block brute force source, change SNMP community strings, restrict SNMP to internal-only, verify device configuration exposure.

### OCI-RECONNAISSANCE-126 — Kubernetes API Server Recon
- **Suggested Response:** Block source IP, audit API server RBAC, verify all API access uses authentication, check for unauthorized resource access.

---

## Domain 8: Database Security (7 rules)

### OCI-DATABASE-001/011/013/020 — CVE-2026-21962 Weblogic Proxy Plug-in (4 instances)
- **Detects:** Improper access control in Oracle HTTP Server / Weblogic Proxy Plug-in
- **MITRE:** T1110, T1078 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Apply Oracle CPU patches immediately, isolate affected server, audit for unauthorized data access, review WAF logs for exploitation patterns.

### OCI-DATABASE-009/018/019 — CVE-2019-1068 SQL Server RCE (3 instances)
- **Detects:** Microsoft SQL Server remote code execution vulnerability
- **MITRE:** T1059, T1190 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Patch SQL Server, restrict network access to SQL Server ports, audit for unauthorized command execution, check for data exfiltration.

---

## Domain 9: Supply Chain Security (10 rules)

### OCI-SUPPLY_CHAIN-057 — Dependency Confusion Attack
- **Suggested Response:** Audit package registries for conflicting packages, enforce scoped package registries, verify all package sources, remove malicious packages.

### OCI-SUPPLY_CHAIN-058 — Typosquatting Package Install
- **Suggested Response:** Remove typosquatted package, install correct package, audit all dependencies for typosquatting, enforce package allowlists.

### OCI-SUPPLY_CHAIN-059 — Compromised CI/CD Pipeline
- **Suggested Response:** Halt all pipelines, rotate CI/CD credentials, audit pipeline execution history, review all recent builds for tampering, restore from known-good state.

### OCI-SUPPLY_CHAIN-060 — Malicious NPM/PyPI Package
- **Suggested Response:** Remove malicious package, scan all projects for the package, audit for post-install script execution, check for data exfiltration.

### OCI-SUPPLY_CHAIN-061 — Container Image Tampering
- **Suggested Response:** Pull and verify image digests, rebuild from trusted base images, audit container registry access logs, enforce image signing.

### OCI-SUPPLY_CHAIN-062 — Compromised Update Server
- **Suggested Response:** Isolate update server, verify all recent updates, switch to backup update server, audit for malicious updates deployed.

### OCI-SUPPLY_CHAIN-063 — Build Pipeline Injection
- **Suggested Response:** Review all build scripts for unauthorized modifications, audit build logs for injected commands, rotate pipeline secrets, restore from known-good pipeline.

### OCI-SUPPLY_CHAIN-064 — Secret Leakage in CI Logs
- **Suggested Response:** Redact and purge exposed secrets from CI logs, rotate all leaked credentials, audit log access, enforce secret masking in CI configuration.

### OCI-SUPPLY_CHAIN-065 — Unsigned Artifact Deployment
- **Suggested Response:** Remove unsigned artifacts, enforce signing policies, audit deployment logs for unsigned artifacts, implement deployment gates.

### OCI-SUPPLY_CHAIN-066 — Dependency Version Pinning Bypass
- **Suggested Response:** Audit for unpinned dependencies, enforce version pinning policies, review all dependency changes, implement automated dependency review.

---

## Domain 10: Zero-Day & Anomalous Activity (10 rules)

### OCI-ZERO_DAY-087 — Unexpected Process Execution from Web Directory
- **Suggested Response:** Isolate affected host, investigate process binary, check for web shell deployment, review web server logs for exploitation.

### OCI-ZERO_DAY-088 — Anomalous Child Process from Service
- **Suggested Response:** Investigate parent service, check for service exploitation, isolate host, review service account permissions.

### OCI-ZERO_DAY-089 — Unusual Network Connection from System Process
- **Suggested Response:** Block destination IP/domain, identify system process, check for process injection, investigate connection payload.

### OCI-ZERO_DAY-090 — Memory Injection Pattern Detection
- **Suggested Response:** Capture memory dump, analyze for injection techniques, isolate host, investigate injected payload.

### OCI-ZERO_DAY-091 — Unexpected DLL Loading
- **Suggested Response:** Identify loaded DLL, check for DLL hijacking, verify loading process, audit DLL loading paths.

### OCI-ZERO_DAY-092 — Abnormal Token Privilege Elevation
- **Suggested Response:** Investigate process that gained elevated privileges, check for token manipulation, isolate host, audit privilege usage.

### OCI-ZERO_DAY-093 — Process Hollowing Indicator
- **Suggested Response:** Capture memory dump for analysis, identify hollowed process, isolate host, investigate injected code.

### OCI-ZERO_DAY-094 — Reflective DLL Injection
- **Suggested Response:** Capture memory for forensic analysis, identify injected DLL, block injection source, investigate attack chain.

### OCI-ZERO_DAY-095 — Unusual Named Pipe Activity
- **Suggested Response:** Identify pipe creator and connected processes, check for C2 communication via named pipes, isolate host.

### OCI-ZERO_DAY-096 — Anomalous Service Installation
- **Suggested Response:** Review service binary, check for malicious service installation, remove service, investigate installing process.

---

## Domain 11: SQL Injection (5 rules)

### OCI-SQL-INJECTION-013 — CVE-2026-72898 Metabase Exploitation
- **Detects:** Unauthenticated SQL injection in Metabase allowing admin access
- **MITRE:** T1190, T1110, T1078 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Patch Metabase immediately, rotate database credentials, audit Metabase for unauthorized access, check for data exfiltration.

### GHADV-1336 — OpenRemote SQL Injection
- **Detects:** Authenticated SQL injection via Datapoint Crosstab Export
- **MITRE:** T1190
- **Suggested Response:** Upgrade OpenRemote, audit for unauthorized database access, rotate database credentials, check for data exfiltration.

### GHADV-2220 — LangChain4j SQL Injection
- **Detects:** SQL injection via metadata filters in langchain4j-mariadb and langchain4j-pgvector
- **MITRE:** T1190
- **Suggested Response:** Update langchain4j, audit for injection attempts, rotate database credentials, review application logs.

### GHADV-4503 — appsmith SQL Injection
- **Detects:** SQL Injection in FilterDataService via Unsafe DROP TABLE Execution
- **MITRE:** T1190
- **Suggested Response:** Update appsmith, audit for unauthorized table operations, rotate database credentials, check for data loss.

### GHADV-4547 — Spring AI SQL Injection
- **Detects:** SQL Injection in CosmosDBVectorStore.doDelete()
- **MITRE:** T1190
- **Suggested Response:** Update Spring AI, audit for unauthorized deletions, rotate database credentials, check for data loss.

---

## Domain 12: Server-Side Request Forgery (18 rules)

### OCI-SSRF-005/015/017 — CVE-2026-64849 MLflow Exploitation (3 instances)
- **Detects:** SSRF in MLflow allowing access to internal/cloud metadata services
- **MITRE:** T1190 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Patch MLflow, restrict network access from MLflow, audit for metadata service access, check for credential theft.

### OCI-SSRF-006/007/011 — CVE-2026-83548 SMA1000 Appliances (3 instances)
- **Detects:** Unauthenticated SSRF in SonicWall SMA1000 appliances
- **MITRE:** T1110, T1078, T1592, T1190, T1213 | **Compliance:** PCI-DSS-6.5, NIST-800-53-SI-4, GDPR-32A
- **Suggested Response:** Patch SMA1000 firmware, restrict network access, audit for unauthorized operations, check for credential exposure.

### GHADV-0576 — java-client Network Pivot
- **Suggested Response:** Update java-client, restrict directConnect redirects, audit for network pivoting, review AppiumCommandExecutor usage.

### GHADV-1820 — jackson-databind SSRF
- **Suggested Response:** Update jackson-databind, audit for eager DNS resolution, restrict outbound DNS from deserialization contexts.

### GHADV-1888 — OpenAM SSRF
- **Suggested Response:** Patch OpenAM, restrict /sessionservice endpoint, audit for SSRF attempts, check for internal network probing.

### GHADV-2660 — Spring Framework SSRF
- **Suggested Response:** Update Spring Framework, restrict UriComponentsBuilder URL schemes, audit for SSRF attempts, review outbound requests.

### GHADV-2875 — Apache Fesod SSRF
- **Suggested Response:** Update Apache Fesod, restrict UrlImageConverter URLs, audit for SSRF attempts, check for internal network access.

### GHADV-2947 — CC-Tweaked SSRF Bypass
- **Suggested Response:** Update CC-Tweaked, block NAT64 bypass attempts, audit for SSRF, review network configuration.

### GHADV-3090 — Jenkins LDAP Plugin SSRF
- **Suggested Response:** Update Jenkins LDAP Plugin, disable LDAP referrals, audit for referral-based SSRF, review LDAP configuration.

### GHADV-3092 — Jenkins AD Plugin SSRF
- **Suggested Response:** Update Jenkins Active Directory Plugin, disable LDAP referrals, audit for SSRF attempts, review AD configuration.

### GHADV-3470 — Spring AI MCP SSRF
- **Suggested Response:** Update Spring AI MCP, restrict URL fetching, audit for unvalidated URL access, review MCP tool configuration.

### GHADV-4281 — XWiki PlantUML SSRF
- **Suggested Response:** Update XWiki PlantUML macro, restrict 'server' parameter, audit for SSRF attempts, check for internal network access.

### GHADV-4308 — Eclipse BaSyx SSRF
- **Suggested Response:** Update Eclipse BaSyx SDK, restrict outbound requests, audit for SSRF attempts, review BaSyx server configuration.

### GHADV-4441 — Apache Neethi SSRF
- **Suggested Response:** Update Apache Neethi, restrict PolicyReference URIs, audit for remote policy fetching, review XML policy processing.

---

## Domain 13: Execution & Process Activity (10 rules)

### OCI-EXECUTION-137 — PowerShell Suspicious Execution
- **Detects:** Encoded PowerShell, -bypass, hidden window, download cradle patterns
- **Suggested Response:** Isolate host, capture PowerShell script, block execution via AppLocker/Constrained Language Mode, investigate attack chain.

### OCI-EXECUTION-138 — WMI Remote Execution
- **Detects:** WMI-based remote command execution via wmiprvse
- **Suggested Response:** Isolate source and target hosts, audit WMI usage, restrict WMI remote execution, investigate executed commands.

### OCI-EXECUTION-139 — Scheduled Task/At Job Creation
- **Detects:** Suspicious scheduled task creation for persistence or execution
- **Suggested Response:** Review task action, delete malicious tasks, investigate creating process, audit all scheduled tasks.

### OCI-EXECUTION-140 — LSASS Memory Dumping
- **Detects:** procdump, comsvcs.dll minidump, or direct LSASS access
- **Suggested Response:** Isolate host immediately, reset all domain credentials, capture memory for forensics, investigate dumping process.

### OCI-EXECUTION-141 — Living-off-the-Land Binary (LOLBins)
- **Detects:** Abuse of certutil, bitsadmin, mshta, msiexec for download/execution
- **Suggested Response:** Block LOLBin from network access, investigate downloaded payload, isolate host, audit for LOLBin abuse.

### OCI-EXECUTION-142 — CMSTP Execution
- **Detects:** CMSTP.exe used for DLL execution and bypass
- **Suggested Response:** Block CMSTP execution via AppLocker, investigate executed DLL, isolate host, audit for CMSTP abuse.

### OCI-EXECUTION-143 — Remote Service Session Hijacking
- **Detects:** RDP/Terminal Services session hijacking patterns
- **Suggested Response:** Terminate hijacked session, reset user's credentials, audit for data access during session, investigate hijack source.

### OCI-EXECUTION-144 — Container Admin Escape
- **Detects:** Container breakout via privileged mode or volume mount
- **Suggested Response:** Stop container, audit for host-level access, review container configuration, enforce non-privileged container policies.

### OCI-EXECUTION-145 — Kubernetes Exec into Pod
- **Detects:** kubectl exec into sensitive pods
- **Suggested Response:** Audit exec command, review who executed it, check for unauthorized access, restrict kubectl exec permissions via RBAC.

### OCI-EXECUTION-146 — SQL Command Execution via Web App
- **Detects:** SQL injection leading to xp_cmdshell, LOAD_FILE, COPY commands
- **Suggested Response:** Patch web application, block xp_cmdshell, audit for data exfiltration, review database permissions for web app user.

---

*Generated: 2026-09-14 | Source: baseline-rules.json v1.0.0 | 149 rules, 13 domains*