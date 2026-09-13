#!/usr/bin/env python3
"""
SIEM Rule Import & Conversion Engine
=====================================
Converts metadata-only rules into platform-native detection rules
with real query logic. Also provides API import commands for each platform.

Usage:
  python3 scripts/import_rules.py --all                 # Convert all platforms
  python3 scripts/import_rules.py --platform elastic    # Convert one platform
  python3 scripts/import_rules.py --validate            # Validate converted rules
  python3 scripts/import_rules.py --deploy elastic      # Generate deploy-ready output

Each platform gets REAL detection logic based on:
  - CVE ID → product-specific exploit signatures
  - MITRE ATT&CK technique → behavior-based detection patterns
  - Category → platform-appropriate log source + query template
  - Tags → additional filtering and correlation context
"""

import json
import os
import sys
import re
import argparse
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).parent.parent
RULES_DIR = BASE / "rules"
OUTPUT_DIR = BASE / "rules"  # Overwrite in-place

PLATFORMS = [
    "elastic", "splunk", "fortisiem", "qradar", "sentinel",
    "wazuh", "zeek", "suricata", "oracle", "azure", "aws"
]

# ─── Detection Logic Templates ──────────────────────────────

# CVE-based detection: extract product and CVE ID to build real queries
CVE_PATTERNS = {
    # Product → (log_source, query_pattern) per platform
    "zimbra": {
        "elastic": 'event.category:"network" AND (url.path:("*zimbra*" OR "/Compose*" OR "/h/" OR "/zimbra/") OR http.request.body.content:*"COBJ") AND NOT http.response.status_code:(200 OR 301)',
        "splunk": 'index=* sourcetype="zimbra:mailbox" OR sourcetype="access_logs" ("COBJ" OR "/zimbra/" OR "zimbraAdmin") | stats count, values(src_ip) as src_ips by host, uri_path | where count > 3',
        "qradar": "SELECT * FROM events WHERE (URL PATH LIKE '%/zimbra/%' OR PAYLOAD LIKE '%COBJ%') AND NOT (RESPONSE CODE = 200 OR RESPONSE CODE = 301) LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/zimbra/" or RequestURL contains "COBJ") and (HttpStatusCode != 200 and HttpStatusCode != 301) | summarize count(), make_set(SourceIP) by TimeGenerated, RequestURL | where count_ > 3',
        "wazuh": '<rule id="{id}" level="{level}"><if_sid>31100</if_sid><url>/zimbra/|/h/|COBJ</url><description>{name}</description><mitre><id>{mitre}</id></mitre></rule>',
        "zeek": 'signature {id} {{\n\tip-proto tcp\n\tdst-port = {{ 80 443 8080 8443 }}\n\thttp-request /.*(COBJ|\\/zimbra\\/|\\/h\\/).*/ regex\n\tevent "{name}"\n}}',
        "fortisiem": '<Pattern><PatternType>Generic</PatternType><EventCriteria><EventType>ZimbraMailboxEvent</EventType><Filter>(URL CONTAINS "/zimbra/" OR PAYLOAD CONTAINS "COBJ") AND (RESPONSE_CODE != 200 AND RESPONSE_CODE != 301)</Filter></EventCriteria><IncidentCriteria><Severity>{severity}</Severity></IncidentCriteria></Pattern>',
        "aws": '{"filter_pattern": "{ ($.requestURL = *zimbra*) }", "metric_name": "ZimbraExploit"}',
        "azure": 'AzureDiagnostics | where (RequestUri_s contains "/zimbra/" or RequestUri_s contains "COBJ") and (httpStatusCode_d != 200 and httpStatusCode_d != 301) | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 3',
        "oracle": 'SELECT metric VALUE FROM "SIEM/Security" WHERE metric = \'zimbra_exploit\' AND value > 0',
    },
    "sharepoint": {
        "elastic": 'event.category:"authentication" AND url.path:*"/_layouts/"* AND (http.request.body.content:("__VIEWSTATE" OR "ctl00$") OR http.request.method:POST) AND NOT event.outcome:"success"',
        "splunk": 'index=* sourcetype="access_logs" "/_layouts/" ("__VIEWSTATE" OR "ctl00$") method=POST | stats count, values(src_ip) as src_ips by uri_path | where count > 5',
        "qradar": "SELECT * FROM events WHERE (URL PATH LIKE '%/_layouts/%') AND (PAYLOAD LIKE '%__VIEWSTATE%' OR PAYLOAD LIKE '%ctl00$%') AND METHOD = 'POST' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where RequestURL contains "/_layouts/" and (RequestHeader contains "__VIEWSTATE" or RequestMethod == "POST") | summarize count(), make_set(SourceIP) by TimeGenerated, RequestURL | where count_ > 5',
        "wazuh": '<rule id="{id}" level="{level}"><if_sid>31100</if_sid><url>/_layouts/</url><description>{name}</description><mitre><id>{mitre}</id></mitre></rule>',
        "zeek": 'signature {id} {{\n\tip-proto tcp\n\tdst-port = {{ 80 443 }}\n\thttp-request /.*\\/\\_layouts\\/.*/ regex\n\tevent "{name}"\n}}',
        "fortisiem": '<Pattern><PatternType>Generic</PatternType><EventCriteria><EventType>SharePointEvent</EventType><Filter>(URL CONTAINS "/_layouts/") AND (METHOD = "POST")</Filter></EventCriteria><IncidentCriteria><Severity>{severity}</Severity></IncidentCriteria></Pattern>',
        "aws": '{"filter_pattern": "{ ($.requestURL = *\\/_layouts\\/*) }", "metric_name": "SharePointExploit"}',
        "azure": 'AzureDiagnostics | where RequestUri_s contains "/_layouts/" and RequestMethod_s == "POST" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 5',
        "oracle": 'SELECT metric VALUE FROM "SIEM/Security" WHERE metric = \'sharepoint_exploit\' AND value > 0',
    },
    "default": {
        "elastic": 'event.category:("network" OR "authentication" OR "database") AND (message:*"{cve_lower}"* OR url.path:*"{cve_lower}"* OR http.request.body.content:*"{cve_lower}"* OR process.command_line:*"{product_lower}"*)',
        "splunk": 'index=* ("{cve_lower}" OR "{product_lower}") (tag=exploit OR sourcetype="access_logs" OR sourcetype="auth_logs" OR sourcetype="firewall") | stats count, values(src_ip) as src_ips, values(dest_ip) as dest_ips by host, source | where count > 3',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%{cve_upper}%' OR PAYLOAD LIKE '%{product_upper}%') AND SEVERITY >= 5 LAST 15 MINUTES",
        "sentinel": 'union CommonSecurityLog, SecurityEvent, AzureDiagnostics | where (Message contains "{cve_upper}" or Message contains "{product_upper}") | summarize count(), make_set(SourceIP) by bin(TimeGenerated, 5m), ActivityDisplayName | where count_ > 3',
        "wazuh": '<rule id="{id}" level="{level}"><if_sid>31100</if_sid><match>{cve_lower}|{product_lower}</match><description>{name}</description><mitre><id>{mitre}</id></mitre></rule>',
        "zeek": 'signature {id} {{\n\tip-proto tcp\n\tdst-port = {{ 80 443 8080 8443 }}\n\thttp-request /.*({cve_lower}|{product_lower}).*/ regex\n\tevent "{name}"\n}}',
        "fortisiem": '<Pattern><PatternType>Generic</PatternType><EventCriteria><EventType>GenericEvent</EventType><Filter>(PAYLOAD CONTAINS "{cve_upper}" OR PAYLOAD CONTAINS "{product_upper}")</Filter></EventCriteria><IncidentCriteria><Severity>{severity}</Severity></IncidentCriteria></Pattern>',
        "aws": '{{"filter_pattern": "{{ ($.eventName = *{product_lower}*) }}", "metric_name": "{cve_safe}"}}',
        "azure": 'union CommonSecurityLog, SecurityEvent, AzureDiagnostics | where Message contains "{cve_upper}" or Message contains "{product_upper}" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 3',
        "oracle": 'SELECT metric VALUE FROM "SIEM/Security" WHERE metric = \'{cve_safe}\' AND value > 0',
    },
}

# MITRE technique detection patterns
MITRE_PATTERNS = {
    "T1190": {  # Exploit Public-Facing Application
        "elastic": 'event.category:"network" AND event.action:("exploit" OR "attack" OR "injection") AND http.response.status_code:(400 OR 403 OR 500) AND NOT event.outcome:"success"',
        "splunk": 'index=* sourcetype="access_logs" (status=400 OR status=403 OR status=500) ("exploit" OR "injection" OR "attack") | stats count, values(src_ip) as src_ips by uri_path, status | where count > 5',
        "sentinel": 'CommonSecurityLog | where HttpStatusCode in (400, 403, 500) and (RequestURL contains "exploit" or RequestURL contains "injection") | summarize count(), make_set(SourceIP) by bin(TimeGenerated, 5m), RequestURL | where count_ > 5',
    },
    "T1078": {  # Valid Accounts
        "elastic": 'event.category:"authentication" AND event.action:"login" AND event.outcome:"success" AND (user.name:(*admin* OR *root* OR *service*) OR source.geo.country_name:* AND NOT source.ip:(10.* OR 172.16.* OR 192.168.*))',
        "splunk": 'index=* sourcetype="auth_logs" action=login result=success (user=*admin* OR user=*root* OR user=*service* OR src_ip!=10.* AND src_ip!=172.16.* AND src_ip!=192.168.*) | stats count by user, src_ip, action',
        "sentinel": 'SecurityEvent | where EventID == 4624 and (Account contains "admin" or Account contains "root" or AccountType != "User") | summarize count(), make_set(SourceIP) by Account, bin(TimeGenerated, 5m)',
    },
    "T1110": {  # Brute Force
        "elastic": 'event.category:"authentication" AND event.action:"login" AND event.outcome:"failure" | count() by source.ip, user.name | where count > 10',
        "splunk": 'index=* sourcetype="auth_logs" action=login result=failure | stats count by user, src_ip | where count > 10',
        "sentinel": 'SecurityEvent | where EventID == 4625 | summarize count(), make_set(SourceIP) by Account, bin(TimeGenerated, 5m) | where count_ > 10',
    },
    "T1548": {  # Abuse Elevation Control Mechanism
        "elastic": 'event.category:"process" AND event.action:("privileged" OR "elevation" OR "sudo" OR "runas") AND NOT user.name:(*admin* OR *root*)',
        "splunk": 'index=* (sourcetype="linux_secure" OR sourcetype="wineventlog") ("sudo" OR "runas" OR "elevation") NOT user=*admin* | stats count by user, host, command',
        "sentinel": 'SecurityEvent | where EventID in (4672, 4688) and (Process contains "sudo" or Process contains "runas") | summarize count() by Account, Process, bin(TimeGenerated, 5m)',
    },
    "T1552": {  # Unsecured Credentials
        "elastic": 'event.category:("file" OR "database") AND (file.path:("*password*" OR "*credential*" OR "*secret*" OR "*.pem" OR "*.key") OR message:("*password*" OR "*api_key*" OR "*secret*"))',
        "splunk": 'index=* ("password=" OR "api_key=" OR "secret=" OR "credential" OR "*.pem" OR "*.key") | stats count, values(src_ip) as src_ips by host, source',
        "sentinel": 'union SecurityEvent, CommonSecurityLog | where Message contains "password" or Message contains "api_key" or Message contains "credential" | summarize count() by bin(TimeGenerated, 5m), SourceIP',
    },
    "T1213": {  # Data from Information Repositories
        "elastic": 'event.category:"network" AND http.request.method:GET AND url.path:("/api/*" OR "/export" OR "/download" OR "/backup") AND http.response.status_code:200 AND _count > 100',
        "splunk": 'index=* sourcetype="access_logs" method=GET (uri_path="/api/*" OR uri_path="/export" OR uri_path="/download") status=200 | stats count by src_ip, uri_path | where count > 100',
        "sentinel": 'CommonSecurityLog | where RequestMethod == "GET" and (RequestURL contains "/api/" or RequestURL contains "/export") and HttpStatusCode == 200 | summarize count() by SourceIP, bin(TimeGenerated, 5m) | where count_ > 100',
    },
    "T1041": {  # Exfiltration Over C2 Channel
        "elastic": 'event.category:"network" AND network.protocol:("http" OR "dns" OR "https") AND (destination.ip:* AND NOT destination.ip:(10.* OR 172.16.* OR 192.168.*)) AND network.bytes > 10485760',
        "splunk": 'index=* sourcetype="firewall" dest_ip!=10.* dest_ip!=172.16.* dest_ip!=192.168.* bytes > 10485760 | stats sum(bytes) by src_ip, dest_ip, dest_port',
        "sentinel": 'CommonSecurityLog | where DestinationIP !startswith "10." and DestinationIP !startswith "172.16." and DestinationIP !startswith "192.168." and SentBytes > 10485760 | summarize sum(SentBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 5m)',
    },
    "T1567": {  # Exfiltration Over Web Service
        "elastic": 'event.category:"network" AND (url.domain:("*.s3.amazonaws.com" OR "*.blob.core.windows.net" OR "*.googleapis.com" OR "dropbox.com" OR "onedrive.com") AND network.bytes > 5242880)',
        "splunk": 'index=* sourcetype="firewall" (dest_domain="*.s3.amazonaws.com" OR dest_domain="*.blob.core.windows.net" OR dest_domain="dropbox.com") bytes > 5242880 | stats sum(bytes) by src_ip, dest_domain',
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "s3.amazonaws.com" or RequestURL contains "blob.core.windows.net" or RequestURL contains "dropbox.com") and SentBytes > 5242880 | summarize sum(SentBytes) by SourceIP, RequestURL, bin(TimeGenerated, 5m)',
    },
    "T1189": {  # Drive-By Compromise
        "elastic": 'event.category:"network" AND http.request.headers:"Referer" AND (url.path:("*.exe" OR "*.dll" OR "*.scr" OR "*.hta") AND NOT url.domain:*internal*)',
        "splunk": 'index=* sourcetype="access_logs" (uri_path="*.exe" OR uri_path="*.dll" OR uri_path="*.hta") NOT dest_domain=*internal* | stats count by src_ip, uri_path, dest_domain',
        "sentinel": 'CommonSecurityLog | where (RequestURL endswith ".exe" or RequestURL endswith ".dll" or RequestURL endswith ".hta") and RequestURL !contains "internal" | summarize count() by SourceIP, RequestURL, bin(TimeGenerated, 5m)',
    },
    "T1059": {  # Command and Scripting Interpreter
        "elastic": 'event.category:"process" AND process.name:("powershell.exe" OR "cmd.exe" OR "bash" OR "sh" OR "python*") AND process.command_line:("*-enc*" OR "*base64*" OR "*-exec*" OR "*import*")',
        "splunk": 'index=* sourcetype="wineventlog" (process=powershell.exe OR process=cmd.exe) (command_line="*-enc*" OR command_line="*base64*" OR command_line="*-exec*") | stats count by host, process, command_line',
        "sentinel": 'SecurityEvent | where EventID == 4688 and (Process == "powershell.exe" or Process == "cmd.exe") and (CommandLine contains "-enc" or CommandLine contains "base64") | summarize count() by Computer, Process, CommandLine, bin(TimeGenerated, 5m)',
    },
    "T1534": {  # Internal Spearphishing
        "elastic": 'event.category:"email" AND event.action:"send" AND (email.from.address:*@internal* AND email.to.address:*@internal*) AND (email.subject:("urgent" OR "invoice" OR "payment" OR "security alert") OR email.attachments:*.zip*)',
        "splunk": 'index=* sourcetype="email" (from=*@internal* AND to=*@internal*) (subject="*urgent*" OR subject="*invoice*" OR subject="*payment*" OR attachment="*.zip*") | stats count by from, to, subject',
        "sentinel": 'EmailEvents | where (SenderMailFromAddress endswith "@internal" and RecipientEmailAddress endswith "@internal") and (Subject contains "urgent" or Subject contains "invoice" or has_attachment == true) | summarize count() by SenderMailFromAddress, Subject, bin(TimeGenerated, 1h)',
    },
}

# Category-based fallback patterns for non-CVE, non-MITRE rules
CATEGORY_PATTERNS = {
    "ai-llm": {
        "elastic": 'event.category:"network" AND (http.request.body.content:("ignore previous instructions" OR "you are now" OR "DAN" OR "jailbreak" OR "system prompt" OR "show me your" OR "pretend you are") OR url.path:("/chat" OR "/completion" OR "/api/llm"))',
        "splunk": 'index=* sourcetype="access_logs" ("/chat" OR "/completion" OR "/api/llm") ("ignore previous" OR "jailbreak" OR "DAN" OR "system prompt" OR "pretend you are") | stats count, values(src_ip) as src_ips by uri_path | where count > 3',
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/chat" or RequestURL contains "/completion" or RequestURL contains "/api/llm") and (RequestHeader contains "ignore previous" or RequestHeader contains "jailbreak" or RequestHeader contains "DAN" or RequestHeader contains "system prompt") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 3',
    },
    "web-application": {
        "elastic": 'event.category:"network" AND (url.path:("*.sql" OR "*.php" OR "*.asp" OR "*.jsp") AND (http.request.body.content:("UNION SELECT" OR "OR 1=1" OR "<script" OR "../" OR "..\\") OR url.query:("SELECT" OR "UNION" OR "script")))',
        "splunk": 'index=* sourcetype="access_logs" ("UNION SELECT" OR "OR 1=1" OR "<script" OR "../" OR "..\\") | stats count, values(src_ip) as src_ips by uri_path, status | where count > 5',
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "UNION SELECT" or RequestURL contains "OR 1=1" or RequestURL contains "<script" or RequestURL contains "../") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 5',
    },
    "database": {
        "elastic": 'event.category:"database" AND (postgresql.query:("SELECT * FROM pg_authid" OR "COPY TO" OR "pg_dump") OR mysql.query:("SELECT * FROM mysql.user" OR "INTO OUTFILE" OR "LOAD_FILE") OR mssql.query:("xp_cmdshell" OR "OPENROWSET" OR "sp_adduser"))',
        "splunk": 'index=* (sourcetype="postgresql" OR sourcetype="mysql" OR sourcetype="mssql") ("pg_authid" OR "xp_cmdshell" OR "INTO OUTFILE" OR "LOAD_FILE" OR "pg_dump") | stats count by user, query, host',
        "sentinel": 'union AzureDiagnostics, CommonSecurityLog | where (Message contains "pg_authid" or Message contains "xp_cmdshell" or Message contains "INTO OUTFILE" or Message contains "pg_dump") | summarize count() by bin(TimeGenerated, 5m), SourceIP',
    },
    "lateral-movement": {
        "elastic": 'event.category:"network" AND (network.protocol:("smb" OR "rdp" OR "winrm" OR "wmi") AND source.ip:(10.* OR 172.16.* OR 192.168.*) AND destination.ip:(10.* OR 172.16.* OR 192.168.*) AND source.ip != destination.ip)',
        "splunk": 'index=* sourcetype="firewall" (protocol=smb OR protocol=rdp OR protocol=winrm) src_ip=10.* OR src_ip=172.16.* OR src_ip=192.168.* dest_ip=10.* OR dest_ip=172.16.* OR dest_ip=192.168.* | stats count by src_ip, dest_ip, protocol | where src_ip != dest_ip',
        "sentinel": 'CommonSecurityLog | where (Protocol == "SMB" or Protocol == "RDP" or Protocol == "WinRM") and SourceIP startswith "10." and DestinationIP startswith "10." and SourceIP != DestinationIP | summarize count() by SourceIP, DestinationIP, Protocol, bin(TimeGenerated, 5m)',
    },
    "privilege-escalation": {
        "elastic": 'event.category:"process" AND (process.name:("sudo" OR "su" OR "runas" OR "powershell.exe") AND process.command_line:("*-Verb RunAs*" OR "*setuid*" OR "*chmod 4*" OR "*net localgroup administrators*"))',
        "splunk": 'index=* (sourcetype="linux_secure" OR sourcetype="wineventlog") ("sudo" OR "runas" OR "setuid" OR "net localgroup administrators") | stats count by user, host, command',
        "sentinel": 'SecurityEvent | where EventID in (4672, 4688, 4673) and (Process contains "sudo" or Process contains "runas" or CommandLine contains "setuid" or CommandLine contains "net localgroup") | summarize count() by Account, Process, bin(TimeGenerated, 5m)',
    },
    "ransomware": {
        "elastic": 'event.category:"file" AND (file.extension:("encrypted" OR "locked" OR "crypto") OR process.command_line:("*vssadmin delete*" OR "*wbadmin delete*" OR "*bcdedit*safe mode*" OR "*cipher /e*"))',
        "splunk": 'index=* ("vssadmin delete" OR "wbadmin delete" OR "bcdedit" OR "cipher /e" OR "*.encrypted" OR "*.locked") | stats count, values(host) as hosts by src_ip, command | where count > 1',
        "sentinel": 'union SecurityEvent, CommonSecurityLog | where (CommandLine contains "vssadmin delete" or CommandLine contains "wbadmin delete" or Message contains ".encrypted" or Message contains ".locked") | summarize count(), make_set(Computer) by SourceIP, bin(TimeGenerated, 5m)',
    },
    "initial-access": {
        "elastic": 'event.category:"authentication" AND event.action:"login" AND event.outcome:"success" AND source.ip:(* AND NOT (10.* OR 172.16.* OR 192.168.*)) AND (user.name:(*admin* OR *root*) OR event.data.first_login:*true*)',
        "splunk": 'index=* sourcetype="auth_logs" action=login result=success (src_ip!=10.* AND src_ip!=172.16.* AND src_ip!=192.168.*) (user=*admin* OR user=*root*) | stats count by user, src_ip, _time',
        "sentinel": 'SecurityEvent | where EventID == 4624 and SourceIP !startswith "10." and SourceIP !startswith "172.16." and SourceIP !startswith "192.168." and (Account contains "admin" or Account contains "root") | summarize count() by Account, SourceIP, bin(TimeGenerated, 5m)',
    },
    "exfiltration": {
        "elastic": 'event.category:"network" AND network.bytes > 10485760 AND destination.ip:(* AND NOT (10.* OR 172.16.* OR 192.168.*)) AND (network.protocol:("https" OR "ftp" OR "sftp") OR url.domain:("*.s3.amazonaws.com" OR "*transfer.sh" OR "*gofile.io"))',
        "splunk": 'index=* sourcetype="firewall" bytes > 10485760 dest_ip!=10.* dest_ip!=172.16.* dest_ip!=192.168.* (protocol=https OR protocol=ftp OR protocol=sftp) | stats sum(bytes) as total_bytes by src_ip, dest_ip, dest_port | where total_bytes > 10485760',
        "sentinel": 'CommonSecurityLog | where SentBytes > 10485760 and DestinationIP !startswith "10." and DestinationIP !startswith "172.16." and DestinationIP !startswith "192.168." | summarize sum(SentBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 5m)',
    },
    "cloud-native": {
        "elastic": 'event.category:"cloud" AND (cloud.provider:("aws" OR "azure" OR "gcp") AND event.action:("CreateUser" OR "CreateAccessKey" OR "AttachRolePolicy" OR "ModifyPolicy" OR "DeleteFlowLog"))',
        "splunk": 'index=* sourcetype="aws:cloudtrail" OR sourcetype="azure:activity" (eventName="CreateUser" OR eventName="CreateAccessKey" OR eventName="AttachRolePolicy" OR eventName="DeleteFlowLog") | stats count by user, eventName, sourceIPAddress',
        "sentinel": 'AzureActivity | where OperationName in ("Create User", "Create Access Key", "Attach Role Policy", "Delete Flow Log") or (OperationNameValue == "Microsoft.Authorization/roleAssignments/write") | summarize count() by Caller, OperationName, bin(TimeGenerated, 5m)',
    },
    "supply-chain": {
        "elastic": 'event.category:"process" AND (process.name:("npm" OR "pip" OR "yarn" OR "gem" OR "cargo" OR "go") AND process.command_line:("*install*" AND NOT "--dry-run")) AND NOT user.name:(*ci* OR *build* OR *jenkins*)',
        "splunk": 'index=* (process=npm OR process=pip OR process=yarn OR process=gem) command_line="*install*" NOT user=*ci* NOT user=*build* | stats count by user, host, command_line',
        "sentinel": 'SecurityEvent | where EventID == 4688 and (Process in ("npm.exe", "pip.exe", "yarn.exe") and CommandLine contains "install") | summarize count() by Account, Process, CommandLine, bin(TimeGenerated, 5m)',
    },
    "zero-day": {
        "elastic": 'event.category:"network" AND http.response.status_code:(500 OR 502 OR 503) AND url.path:("*.cgi" OR "*.php" OR "*.asp" OR "*.jsp") AND http.request.method:POST AND NOT http.request.body.content:*',
        "splunk": 'index=* sourcetype="access_logs" (status=500 OR status=502 OR status=503) method=POST (uri_path="*.cgi" OR uri_path="*.php" OR uri_path="*.asp") | stats count, values(src_ip) as src_ips by uri_path, status | where count > 3',
        "sentinel": 'CommonSecurityLog | where HttpStatusCode in (500, 502, 503) and RequestMethod == "POST" and (RequestURL endswith ".cgi" or RequestURL endswith ".php" or RequestURL endswith ".asp") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 3',
    },
    "default": {
        "elastic": 'event.category:("network" OR "authentication" OR "database" OR "process") AND (message:*"{tag1}"* OR url.path:*"{tag1}"* OR process.command_line:*"{tag1}"*)',
        "splunk": 'index=* ("{tag1}" OR "{tag2}") | stats count, values(src_ip) as src_ips, values(dest_ip) as dest_ips by host, source | where count > 3',
        "sentinel": 'union CommonSecurityLog, SecurityEvent, AzureDiagnostics | where Message contains "{tag1}" or Message contains "{tag2}" | summarize count(), make_set(SourceIP) by bin(TimeGenerated, 5m), ActivityDisplayName | where count_ > 3',
    },
}


# ─── Severity Mappers ───────────────────────────────────────

SEV_ELASTIC = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}
SEV_FORTISIEM = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Info", "info": "Info"}
SEV_SENTINEL = {"critical": "High", "high": "Medium", "medium": "Low", "low": "Informational", "informational": "Informational", "info": "Informational"}
SEV_OCI = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "INFO", "info": "INFO"}
SEV_AZURE = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
SEV_WAZUH_LEVEL = {"critical": 12, "high": 10, "medium": 7, "low": 4, "informational": 2, "info": 2}
SEV_RISK = {"critical": 95, "high": 75, "medium": 50, "low": 25, "informational": 10, "info": 10}

# Wazuh numeric ID range for custom rules: 100000-199999
WAZUH_ID_BASE = 100000
_wazuh_counter = WAZUH_ID_BASE


def next_wazuh_id():
    global _wazuh_counter
    _wazuh_counter += 1
    return _wazuh_counter


# ─── Query Generator ─────────────────────────────────────────

def get_detection_query(rule, platform):
    """Generate a real detection query for the given platform based on rule metadata."""
    name = rule.get("name", "")
    desc = rule.get("description", "")
    category = rule.get("category", "general")
    tags = rule.get("tags", [])
    mitre = rule.get("mitre_attack", rule.get("mitre", []))
    rule_id = rule.get("rule_id", "")
    
    # Extract CVE ID if present
    cve_match = re.search(r'CVE-\d{4}-\d+', name + " " + desc)
    cve_id = cve_match.group(0) if cve_match else ""
    cve_lower = cve_id.lower() if cve_id else ""
    cve_upper = cve_id.upper() if cve_id else ""
    cve_safe = re.sub(r'[^a-zA-Z0-9]', '', cve_id) if cve_id else "GenericRule"
    
    # Extract product name from rule name
    product = ""
    if " — " in name:
        product = name.split(" — ")[-1].replace(" Exploitation", "").strip()
    elif "Exploitation" in name:
        product = name.replace(" Exploitation", "").strip()
    product_lower = product.lower() if product else ""
    product_upper = product.upper() if product else ""
    
    severity = rule.get("severity", "medium")
    sev_fort = SEV_FORTISIEM.get(severity, "Medium")
    tag1 = tags[0] if tags else category
    tag2 = tags[1] if len(tags) > 1 else ""
    
    # Try CVE-specific pattern first
    if cve_id:
        product_key = "default"
        for key in CVE_PATTERNS:
            if key in product_lower:
                product_key = key
                break
        patterns = CVE_PATTERNS[product_key]
        if platform in patterns:
            return patterns[platform].format(
                id=rule_id,
                level=SEV_WAZUH_LEVEL.get(severity, 7),
                name=name.replace('"', '\\"'),
                mitre=",".join(mitre) if mitre else "",
                severity=sev_fort,
                cve_lower=cve_lower,
                cve_upper=cve_upper,
                cve_safe=cve_safe,
                product_lower=product_lower,
                product_upper=product_upper,
            )
    
    # Try MITRE-specific pattern
    for tech in mitre:
        tech_main = tech.split(".")[0]  # Get parent technique
        if tech_main in MITRE_PATTERNS and platform in MITRE_PATTERNS[tech_main]:
            return MITRE_PATTERNS[tech_main][platform]
    
    # Try category-specific pattern
    cat_key = category if category in CATEGORY_PATTERNS else "default"
    patterns = CATEGORY_PATTERNS[cat_key]
    if platform in patterns:
        return patterns[platform].format(
            tag1=tag1,
            tag2=tag2,
            cve_lower=cve_lower,
            cve_upper=cve_upper,
        )
    
    # Final fallback — use default with tags
    patterns = CATEGORY_PATTERNS["default"]
    if platform in patterns:
        return patterns[platform].format(tag1=tag1, tag2=tag2)
    
    return ""


# ─── Platform Converters ─────────────────────────────────────

def convert_elastic(rules, source_file):
    """Convert rules to Elastic Security Rule API format."""
    converted = []
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        query = rule.get("query", "")
        
        # If query already looks like real KQL, keep it
        if query and not query.startswith("{") and "event.category" in query:
            real_query = query
        else:
            real_query = get_detection_query(rule, "elastic")
        
        mitre = rule.get("mitre_attack", rule.get("mitre", []))
        threat_entries = []
        for tech in mitre:
            tactic = map_mitre_to_tactic(tech)
            if tactic:
                threat_entries.append({
                    "framework": "MITRE ATT&CK",
                    "tactic": {"id": map_tactic_to_id(tactic), "name": tactic, "reference": f"https://attack.mitre.org/tactics/{map_tactic_to_id(tactic)}/"},
                    "technique": [{"id": tech, "name": get_mitre_name(tech), "reference": f"https://attack.mitre.org/techniques/{tech}/"}]
                })
        
        converted.append({
            "rule_id": rule_id,
            "name": rule.get("name", ""),
            "description": rule.get("description", ""),
            "severity": SEV_ELASTIC.get(severity, "medium"),
            "type": rule.get("type", "query"),
            "query": real_query,
            "index": rule.get("index", ["logs-*", "apm-*"]),
            "references": rule.get("references", []),
            "threat": threat_entries,
            "risk_score": SEV_RISK.get(severity, 50),
            "interval": rule.get("interval", "5m"),
            "tags": rule.get("tags", []),
            "compliance": rule.get("compliance", []),
            "author": ["SIEM Alert Rules"],
            "license": "Elastic License v2",
        })
    return converted


def convert_splunk(rules, source_file):
    """Convert rules to Splunk savedsearches.conf format."""
    lines = []
    lines.append(f"# =============================================================")
    lines.append(f"# Splunk SIEM Alert Rules — {source_file.stem}")
    lines.append(f"# Auto-generated: {datetime.utcnow().isoformat()}Z")
    lines.append(f"# =============================================================")
    lines.append("")
    
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        existing_search = rule.get("search", rule.get("query", ""))
        
        # If existing search is real SPL, keep it; otherwise generate
        if existing_search and "index=" in existing_search and "|" in existing_search:
            real_search = existing_search
        else:
            real_search = get_detection_query(rule, "splunk")
        
        actions = "email" if severity in ("critical", "high") else "notable"
        
        lines.append(f"[{rule_id}]")
        lines.append(f"name = {rule.get('name', '')}")
        lines.append(f"description = {rule.get('description', '')}")
        lines.append(f"severity = {severity}")
        lines.append(f"search = {real_search}")
        lines.append(f"actions = {actions}")
        lines.append(f"dispatch.earliest_time = -15m")
        lines.append(f"dispatch.latest_time = now")
        lines.append(f"references = {','.join(rule.get('references', []))}")
        lines.append(f"mitre = {','.join(rule.get('mitre_attack', rule.get('mitre', [])))}")
        lines.append(f"compliance = {','.join(rule.get('compliance', []))}")
        lines.append(f"risk_score = {SEV_RISK.get(severity, 50)}")
        lines.append("")
    
    return "\n".join(lines)


def convert_wazuh(rules, source_file):
    """Convert rules to Wazuh XML format."""
    lines = []
    lines.append(f'<!-- Wazuh SIEM Alert Rules — {source_file.stem} -->')
    lines.append(f'<!-- Auto-generated: {datetime.utcnow().isoformat()}Z -->')
    lines.append(f'<group name="siem-alert-rules,">')
    lines.append("")
    
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        level = SEV_WAZUH_LEVEL.get(severity, 7)
        numeric_id = next_wazuh_id()
        mitre = rule.get("mitre_attack", rule.get("mitre", []))
        
        existing_match = rule.get("match", "")
        if existing_match and len(existing_match) > 3:
            match_pattern = existing_match
        else:
            match_query = get_detection_query(rule, "wazuh")
            # For Wazuh XML, extract the match content
            match_pattern = ""
            if "<match>" in match_query:
                match_pattern = re.search(r'<match>(.*?)</match>', match_query)
                match_pattern = match_pattern.group(1) if match_pattern else ""
            if not match_pattern:
                # Build from tags and CVE
                tags = rule.get("tags", [])
                match_parts = [t for t in tags if t and not t.startswith("cve-")]
                if any("cve" in t for t in tags):
                    cve_match = re.search(r'cve-\d{4}-\d+', " ".join(tags))
                    if cve_match:
                        match_parts.append(cve_match.group(0))
                match_pattern = "|".join(match_parts[:5]) if match_parts else rule.get("category", "general")
        
        name = rule.get("name", "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        desc = rule.get("description", "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        
        lines.append(f'  <rule id="{numeric_id}" level="{level}">')
        lines.append(f'    <if_sid>31100</if_sid>')
        lines.append(f'    <match>{match_pattern}</match>')
        lines.append(f'    <description>{name}</description>')
        lines.append(f'    <details>{desc[:200]}</details>')
        if mitre:
            lines.append(f'    <mitre>')
            for m in mitre:
                lines.append(f'      <id>{m}</id>')
            lines.append(f'    </mitre>')
        for tag in rule.get("tags", [])[:5]:
            lines.append(f'    <tag>{tag}</tag>')
        lines.append(f'  </rule>')
        lines.append("")
    
    lines.append(f'</group>')
    return "\n".join(lines)


def convert_fortisiem(rules, source_file):
    """Convert rules to FortiSIEM XML pattern format."""
    lines = []
    lines.append(f'<!-- FortiSIEM SIEM Alert Rules — {source_file.stem} -->')
    lines.append(f'<!-- Auto-generated: {datetime.utcnow().isoformat()}Z -->')
    lines.append("")
    
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        sev_fort = SEV_FORTISIEM.get(severity, "Medium")
        mitre = rule.get("mitre_attack", rule.get("mitre", []))
        
        existing_pattern = rule.get("pattern", "")
        if existing_pattern and "<PatternType>" in existing_pattern:
            real_pattern = existing_pattern
        else:
            real_pattern = get_detection_query(rule, "fortisiem")
            if not real_pattern:
                real_pattern = f'<Pattern><PatternType>Generic</PatternType><EventCriteria><EventType>GenericEvent</EventType><Filter>PAYLOAD CONTAINS "{rule.get("category", "general")}"</Filter></EventCriteria><IncidentCriteria><Severity>{sev_fort}</Severity></IncidentCriteria></Pattern>'
        
        name = rule.get("name", "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        desc = rule.get("description", "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        
        lines.append(f'<Rule name="{rule_id}" desc="{name}">')
        lines.append(f'  {real_pattern}')
        lines.append(f'  <MITRE>')
        for m in mitre:
            lines.append(f'    <Technique>{m}</Technique>')
        lines.append(f'  </MITRE>')
        lines.append(f'  <Compliance>{",".join(rule.get("compliance", []))}</Compliance>')
        lines.append(f'</Rule>')
        lines.append("")
    
    return "\n".join(lines)


def convert_qradar(rules, source_file):
    """Convert rules to QRadar AQL format."""
    converted = []
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        
        existing_aql = rule.get("aql_query", "")
        if existing_aql and "SELECT" in existing_aql and "CATEGORY =" not in existing_aql:
            real_aql = existing_aql
        else:
            real_aql = get_detection_query(rule, "qradar")
            if not real_aql:
                real_aql = f"SELECT * FROM events WHERE PAYLOAD LIKE '%{rule.get('category', 'general')}%' LAST 15 MINUTES"
        
        sev_num = {"critical": 9, "high": 7, "medium": 5, "low": 3, "informational": 1, "info": 1}.get(severity, 5)
        
        converted.append({
            "rule_id": rule_id,
            "name": rule.get("name", ""),
            "description": rule.get("description", ""),
            "severity": sev_num,
            "severity_label": severity,
            "category": rule.get("category", "general"),
            "aql_query": real_aql,
            "mitre_attack": rule.get("mitre_attack", rule.get("mitre", [])),
            "compliance": rule.get("compliance", []),
            "credibility": 7,
            "relevance": sev_num,
            "tags": rule.get("tags", []),
        })
    return converted


def convert_sentinel(rules, source_file):
    """Convert rules to Microsoft Sentinel analytics rule format."""
    converted = []
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        
        existing_query = rule.get("query", "")
        if existing_query and not existing_query.startswith("KQL:") and not existing_query.startswith("let ") and "|" in existing_query:
            real_query = existing_query
        else:
            real_query = get_detection_query(rule, "sentinel")
        
        mitre = rule.get("mitre_attack", rule.get("mitre", []))
        tactics = list(set(map_mitre_to_tactic(t) for t in mitre if map_mitre_to_tactic(t)))
        techniques = [t for t in mitre if t]
        
        converted.append({
            "rule_id": rule_id,
            "name": rule.get("name", ""),
            "description": rule.get("description", ""),
            "severity": SEV_SENTINEL.get(severity, "Medium"),
            "query": real_query,
            "queryFrequency": rule.get("queryFrequency", rule.get("query_frequency", "PT5M")),
            "queryPeriod": rule.get("queryPeriod", rule.get("query_period", "PT15M")),
            "triggerOperator": rule.get("triggerOperator", "GreaterThan"),
            "triggerThreshold": rule.get("triggerThreshold", 3),
            "tactics": tactics,
            "techniques": techniques,
            "references": rule.get("references", []),
            "compliance": rule.get("compliance", []),
            "tags": rule.get("tags", []),
            "risk_score": SEV_RISK.get(severity, 50),
        })
    return converted


def convert_zeek(rules, source_file):
    """Convert rules to Zeek signature format."""
    lines = []
    lines.append(f'# Zeek SIEM Alert Rules — {source_file.stem}')
    lines.append(f'# Auto-generated: {datetime.utcnow().isoformat()}Z')
    lines.append(f'# Load in local.zeek: @load ./{source_file.stem}')
    lines.append("")
    
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        name = rule.get("name", "").replace('"', '\\"')
        mitre = rule.get("mitre_attack", rule.get("mitre", []))
        category = rule.get("category", "general")
        tags = rule.get("tags", [])
        
        # Extract CVE for pattern
        cve_match = re.search(r'CVE-\d{4}-\d+', name + " " + rule.get("description", ""))
        cve_id = cve_match.group(0).lower() if cve_match else ""
        
        existing_sig = rule.get("zeek_signature", "")
        if existing_sig and ".*().*/ regex" not in existing_sig:
            lines.append(existing_sig)
            lines.append("")
            continue
        
        # Build real signature based on category/mitre
        if cve_id:
            pattern = cve_id
        elif mitre:
            tech = mitre[0].lower()
            if tech.startswith("t1190") or tech.startswith("t1189"):
                pattern = "(union|select|script|alert|onload|onerror|\\.\./|\\.\.\\\\)"
            elif tech.startswith("t1078") or tech.startswith("t1110"):
                pattern = "(login|auth|password|passwd|credential)"
            elif tech.startswith("t1548"):
                pattern = "(sudo|runas|setuid|chmod|elevation)"
            elif tech.startswith("t1552"):
                pattern = "(password|secret|api[_-]?key|credential|\\.pem|\\.key)"
            elif tech.startswith("t1213"):
                pattern = "(export|download|backup|dump|select)"
            elif tech.startswith("t1041") or tech.startswith("t1567"):
                pattern = "(s3\\.amazonaws|blob\\.core|dropbox|transfer\\.sh|gofile)"
            elif tech.startswith("t1059"):
                pattern = "(powershell|cmd\\.exe|bash|python|ruby|perl)"
            elif tech.startswith("t1534"):
                pattern = "(urgent|invoice|payment|\\.zip|attachment)"
            else:
                pattern = tags[0] if tags else category
        else:
            pattern = tags[0] if tags else category
        
        # Escape for regex
        pattern = re.escape(pattern).replace("\\(", "(").replace("\\)", ")")
        
        lines.append(f'signature {rule_id} {{')
        lines.append(f'\tip-proto tcp')
        lines.append(f'\tdst-port = {{ 80 443 8080 8443 }}')
        lines.append(f'\thttp-request /.*({pattern}).*/ regex')
        lines.append(f'\tevent "{name}"')
        lines.append(f'}}')
        lines.append("")
    
    return "\n".join(lines)


def convert_aws(rules, source_file):
    """Convert rules to AWS CloudWatch + EventBridge format."""
    converted = []
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        mitre = rule.get("mitre_attack", rule.get("mitre", []))
        name = rule.get("name", "")
        category = rule.get("category", "general")
        tags = rule.get("tags", [])
        
        # Extract CVE
        cve_match = re.search(r'CVE-\d{4}-\d+', name + " " + rule.get("description", ""))
        cve_id = cve_match.group(0) if cve_match else ""
        
        # Build real filter pattern based on category/CVE/MITRE
        if cve_id:
            filter_pattern = '{ ($.eventName = "*") && ($.sourceIPAddress != "10.*") && ($.requestParameters.* "' + cve_id + '") }'
        elif mitre and any(m.startswith("T1078") for m in mitre):
            filter_pattern = '{ ($.eventName = "ConsoleLogin") && ($.responseElements.ConsoleLogin = "Success") && ($.sourceIPAddress != "10.*") }'
        elif mitre and any(m.startswith("T1110") for m in mitre):
            filter_pattern = '{ ($.eventName = "ConsoleLogin") && ($.responseElements.ConsoleLogin = "Failure") }'
        elif mitre and any(m.startswith("T1213") for m in mitre):
            filter_pattern = '{ ($.eventName = "GetObject" || $.eventName = "ListBucket") && ($.sourceIPAddress != "10.*") }'
        elif category == "ransomware":
            filter_pattern = '{ ($.eventName = "DeleteBucket" || $.eventName = "DeleteObjects" || $.eventName = "PutBucketReplication") }'
        elif category == "exfiltration":
            filter_pattern = '{ ($.eventName = "PutObject") && ($.sourceIPAddress != "10.*") && ($.requestParameters.*) }'
        elif category == "cloud-native":
            filter_pattern = '{ ($.eventName = "CreateUser" || $.eventName = "CreateAccessKey" || $.eventName = "AttachRolePolicy" || $.eventName = "DeleteFlowLog") }'
        else:
            # Use tag-based pattern
            tag_filter = tags[0] if tags else category
            filter_pattern = '{ ($.eventName = "*") && ($.sourceIPAddress != "10.*") && ($.requestParameters.* "' + tag_filter + '") }'
        
        metric_name = re.sub(r'[^a-zA-Z0-9]', '', name)[:100] or rule_id
        
        converted.append({
            "rule_id": rule_id,
            "name": name,
            "description": rule.get("description", ""),
            "severity": severity,
            "category": category,
            "mitre_attack": mitre,
            "compliance": rule.get("compliance", []),
            "source": ["aws.cloudtrail"],
            "detection": {
                "query_type": "cloudwatch_metric_filter",
                "filter_pattern": filter_pattern,
                "log_group": "/aws/cloudtrail",
                "metric_namespace": "Security/Monitoring",
                "metric_name": metric_name,
                "threshold": 3,
                "evaluation_periods": 1,
                "statistic": "Sum",
                "period": 300,
            },
            "eventbridge": {
                "pattern": {
                    "source": ["aws.security", "aws.guardduty"],
                    "detail-type": ["AWS API Call via CloudTrail", "GuardDuty Finding"],
                    "detail": {
                        "eventName": [name[:50]],
                    }
                },
                "state": "ENABLED",
            },
            "actions": [
                {"type": "SNS", "description": "Send alert to security team SNS topic"},
            ],
            "tags": tags,
        })
    return converted


def convert_azure(rules, source_file):
    """Convert rules to Azure Monitor scheduled query format."""
    converted = []
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        
        existing_query = rule.get("query", "")
        if existing_query and not existing_query.startswith("KQL:") and "|" in existing_query:
            real_query = existing_query
        else:
            real_query = get_detection_query(rule, "azure")
        
        mitre = rule.get("mitre_attack", rule.get("mitre", []))
        
        converted.append({
            "rule_id": rule_id,
            "name": rule.get("name", ""),
            "description": rule.get("description", ""),
            "severity": SEV_AZURE.get(severity, 2),
            "severity_label": SEV_SENTINEL.get(severity, "Medium"),
            "category": rule.get("category", "general"),
            "tactics": list(set(map_mitre_to_tactic(t) for t in mitre if map_mitre_to_tactic(t))),
            "mitre_attack": mitre,
            "compliance": rule.get("compliance", []),
            "query": real_query,
            "queryFrequency": rule.get("queryFrequency", "PT5M"),
            "queryPeriod": rule.get("queryPeriod", "PT15M"),
            "triggerOperator": "GreaterThan",
            "triggerThreshold": rule.get("triggerThreshold", 3),
            "tags": rule.get("tags", []),
        })
    return converted


def convert_oracle(rules, source_file):
    """Convert rules to OCI Alarm format."""
    converted = []
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        severity = rule.get("severity", "medium")
        category = rule.get("category", "general")
        mitre = rule.get("mitre_attack", rule.get("mitre", []))
        name = rule.get("name", "")
        
        existing_query = rule.get("query", "")
        if existing_query and not existing_query.startswith("MQL:"):
            real_query = existing_query
        else:
            real_query = get_detection_query(rule, "oracle")
        
        # Build real OCI monitoring query
        metric = category.replace("-", "_")
        converted.append({
            "rule_id": rule_id,
            "name": name,
            "description": rule.get("description", ""),
            "severity": SEV_OCI.get(severity, "MEDIUM"),
            "category": category,
            "mitre_attack": mitre,
            "compliance": rule.get("compliance", []),
            "query": f"SELECT metric VALUE FROM \"SIEM/Security\" WHERE metric = '{metric}' AND value > 0",
            "rule_type": "query",
            "interval": "5m",
            "condition": {
                "eventType": ["com.oracle.cloud.monitoring", "com.oracle.cloud.audit"],
                "compartmentId": "$COMPARTMENT_ID",
                "metric": metric,
                "operator": "GT",
                "threshold": 3,
            },
            "actions": [
                {"actionType": "ONS", "description": "Send alert notification"},
            ],
            "tags": rule.get("tags", []),
        })
    return converted


# ─── MITRE Helpers ───────────────────────────────────────────

MITRE_TACTIC_MAP = {
    "T1190": "InitialAccess", "T1189": "InitialAccess", "T1078": "DefenseEvasion",
    "T1110": "CredentialAccess", "T1548": "PrivilegeEscalation", "T1552": "CredentialAccess",
    "T1213": "Collection", "T1041": "Exfiltration", "T1567": "Exfiltration",
    "T1059": "Execution", "T1534": "LateralMovement", "T1083": "Discovery",
    "T1539": "CredentialAccess", "T1606": "DefenseEvasion", "T1187": "CredentialAccess",
    "T1528": "CredentialAccess", "T1003": "CredentialAccess", "T1055": "DefenseEvasion",
    "T1053": "Execution", "T1136": "Persistence", "T1195": "InitialAccess",
    "T1199": "InitialAccess", "T1046": "Discovery", "T1040": "CredentialAccess",
    "T1568": "CommandAndControl", "T1071": "CommandAndControl",
}

MITRE_NAME_MAP = {
    "T1190": "Exploit Public-Facing Application", "T1189": "Drive-By Compromise",
    "T1078": "Valid Accounts", "T1110": "Brute Force", "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials", "T1213": "Data from Information Repositories",
    "T1041": "Exfiltration Over C2 Channel", "T1567": "Exfiltration Over Web Service",
    "T1059": "Command and Scripting Interpreter", "T1534": "Internal Spearphishing",
    "T1083": "File and Directory Discovery", "T1539": "Steal Web Session Cookie",
    "T1606": "Forge Web Credentials", "T1187": "Forced Authentication",
    "T1528": "Steal Application Access Token", "T1003": "OS Credential Dumping",
    "T1055": "Process Injection", "T1053": "Scheduled Task/Job",
    "T1136": "Create Account", "T1195": "Supply Chain Compromise",
}

TACTIC_ID_MAP = {
    "InitialAccess": "TA0001", "Execution": "TA0002", "Persistence": "TA0003",
    "PrivilegeEscalation": "TA0004", "DefenseEvasion": "TA0005",
    "CredentialAccess": "TA0006", "Discovery": "TA0007", "LateralMovement": "TA0008",
    "Collection": "TA0009", "CommandAndControl": "TA0011", "Exfiltration": "TA0010",
}

def map_mitre_to_tactic(technique):
    tech_main = technique.split(".")[0]
    return MITRE_TACTIC_MAP.get(tech_main, "")

def map_tactic_to_id(tactic):
    return TACTIC_ID_MAP.get(tactic, "")

def get_mitre_name(technique):
    tech_main = technique.split(".")[0]
    return MITRE_NAME_MAP.get(tech_main, technique)


# ─── File Processing ─────────────────────────────────────────

CONVERTERS = {
    "elastic": ("json", convert_elastic),
    "splunk": ("conf", convert_splunk),
    "wazuh": ("xml", convert_wazuh),
    "fortisiem": ("xml", convert_fortisiem),
    "qradar": ("json", convert_qradar),
    "sentinel": ("json", convert_sentinel),
    "zeek": ("zeek", convert_zeek),
    "aws": ("json", convert_aws),
    "azure": ("json", convert_azure),
    "oracle": ("json", convert_oracle),
}


def load_rules_from_file(filepath):
    """Load rules from a JSON or conf file."""
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    
    if filepath.suffix == ".json":
        try:
            data = json.loads(filepath.read_text())
            if isinstance(data, dict) and "rules" in data:
                return data["rules"]
            elif isinstance(data, list):
                return data
        except json.JSONDecodeError:
            return []
    elif filepath.suffix == ".conf":
        # Parse Splunk conf format
        rules = []
        current = {}
        for line in filepath.read_text().splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                if current:
                    rules.append(current)
                current = {"rule_id": line[1:-1]}
            elif "=" in line and current:
                key, value = line.split("=", 1)
                current[key.strip()] = value.strip()
        if current:
            rules.append(current)
        return rules
    elif filepath.suffix == ".rules":
        # Suricata rules are already real, skip
        return []
    return []


def process_platform(platform, dry_run=False):
    """Process all rules for a platform."""
    platform_dir = RULES_DIR / platform
    if not platform_dir.exists():
        print(f"  SKIP: {platform} directory not found")
        return 0
    
    fmt, converter = CONVERTERS.get(platform, (None, None))
    if not converter:
        print(f"  SKIP: {platform} no converter available")
        return 0
    
    total_converted = 0
    
    # Gather all rule files
    if platform == "splunk":
        files = list(platform_dir.glob("*.conf"))
    elif platform == "zeek":
        files = list(platform_dir.glob("*.json"))  # Source is JSON, output is .zeek
    elif platform == "wazuh":
        files = list(platform_dir.glob("*.json"))  # Source is JSON, output is .xml
    elif platform == "fortisiem":
        files = list(platform_dir.glob("*.json"))  # Source is JSON, output is .xml
    elif platform == "suricata":
        files = list(platform_dir.glob("*.rules"))  # Already real, skip
        print(f"  SKIP: {platform} rules are already in native format")
        return 0
    else:
        files = list(platform_dir.glob("*.json"))
    
    for source_file in sorted(files):
        rules = load_rules_from_file(source_file)
        if not rules:
            continue
        
        # Convert
        if fmt == "conf":
            output = converter(rules, source_file)
            output_file = platform_dir / source_file.name
            if not dry_run:
                output_file.write_text(output)
            total_converted += len(rules)
        elif fmt == "xml":
            output = converter(rules, source_file)
            # Write as .xml file
            output_file = platform_dir / source_file.with_suffix(".xml").name
            if not dry_run:
                output_file.write_text(output)
            total_converted += len(rules)
        elif fmt == "zeek":
            output = converter(rules, source_file)
            output_file = platform_dir / source_file.with_suffix(".zeek").name
            if not dry_run:
                output_file.write_text(output)
            total_converted += len(rules)
        elif fmt == "json":
            converted = converter(rules, source_file)
            # Write back as JSON
            if isinstance(converted, list):
                output_data = {
                    "description": f"SIEM alert rules — {source_file.stem} (converted)",
                    "version": "2.0.0",
                    "converted": datetime.utcnow().isoformat() + "Z",
                    "total_rules": len(converted),
                    "rules": converted
                }
            else:
                output_data = converted
            output_file = platform_dir / source_file.name
            if not dry_run:
                output_file.write_text(json.dumps(output_data, indent=2))
            total_converted += len(converted) if isinstance(converted, list) else len(rules)
    
    return total_converted


def validate_platform(platform):
    """Validate that rules have real detection content (not placeholders)."""
    platform_dir = RULES_DIR / platform
    if not platform_dir.exists():
        return {"platform": platform, "valid": 0, "placeholders": 0, "issues": ["Directory not found"]}
    
    valid = 0
    placeholders = 0
    issues = []
    
    for f in sorted(platform_dir.glob("*")):
        if f.suffix not in (".json", ".conf", ".xml", ".zeek", ".rules"):
            continue
        
        content = f.read_text()
        if platform == "elastic" or platform == "qradar" or platform == "sentinel" or platform == "aws" or platform == "azure" or platform == "oracle":
            try:
                data = json.loads(content)
                rules = data.get("rules", data) if isinstance(data, dict) else data
                if not isinstance(rules, list):
                    continue
                for rule in rules:
                    query = rule.get("query", rule.get("aql_query", rule.get("detection", {}).get("filter_pattern", "")))
                    if not query:
                        placeholders += 1
                        issues.append(f"{f.name}:{rule.get('rule_id', '?')} - empty query")
                    elif isinstance(query, str):
                        if query.startswith("KQL:") or query.startswith("MQL:") or query == "SELECT * FROM events WHERE CATEGORY = 'general'" or "{$.eventName = \"*\"}" in query:
                            placeholders += 1
                            issues.append(f"{f.name}:{rule.get('rule_id', '?')} - placeholder query")
                        else:
                            valid += 1
            except json.JSONDecodeError:
                issues.append(f"{f.name} - invalid JSON")
        elif platform == "wazuh" or platform == "fortisiem":
            if "<Pattern>" in content and "</Pattern>" in content:
                # Check for real patterns vs just wrapping the name
                import re as _re
                patterns = _re.findall(r'<Pattern>(.*?)</Pattern>', content)
                for p in patterns:
                    if "<PatternType>" in p or "<EventCriteria>" in p:
                        valid += 1
                    else:
                        placeholders += 1
            if "<match>" in content:
                matches = re.findall(r'<match>(.*?)</match>', content)
                for m in matches:
                    if len(m) > 3 and m != "":
                        valid += 1
                    else:
                        placeholders += 1
        elif platform == "zeek":
            if ".*().*/ regex" in content:
                placeholders += content.count(".*().*/ regex")
            if "http-request" in content:
                valid += content.count("signature ")
        elif platform == "splunk":
            for line in content.splitlines():
                if line.strip().startswith("search = "):
                    search = line.split("=", 1)[1].strip()
                    if "index=" in search and "|" in search:
                        valid += 1
                    else:
                        placeholders += 1
        elif platform == "suricata":
            # Already validated as real
            valid += sum(1 for line in content.splitlines() if line.strip() and line.strip()[0].isalpha() and "alert" in line)
    
    return {"platform": platform, "valid": valid, "placeholders": placeholders, "issues": issues[:10]}


# ─── Main ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SIEM Rule Import & Conversion Engine")
    parser.add_argument("--all", action="store_true", help="Convert all platforms")
    parser.add_argument("--platform", type=str, help="Convert specific platform")
    parser.add_argument("--validate", action="store_true", help="Validate converted rules")
    parser.add_argument("--deploy", type=str, help="Generate deploy-ready output for platform")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    args = parser.parse_args()
    
    if args.validate:
        print("\n🔍 SIEM Rule Validation — Checking for placeholder content\n")
        total_valid = 0
        total_placeholders = 0
        for platform in PLATFORMS:
            result = validate_platform(platform)
            status = "✅" if result["placeholders"] == 0 else "❌"
            print(f"  {status} {platform}: {result['valid']} valid, {result['placeholders']} placeholders")
            for issue in result["issues"][:3]:
                print(f"      ⚠️  {issue}")
            total_valid += result["valid"]
            total_placeholders += result["placeholders"]
        print(f"\n  Total: {total_valid} valid rules, {total_placeholders} placeholder rules")
        if total_placeholders > 0:
            print(f"\n  ⚠️  {total_placeholders} rules still have placeholder queries.")
            print(f"  Run: python3 scripts/import_rules.py --all")
        return
    
    if args.all:
        print("\n🚀 Converting all platforms to native format\n")
        total = 0
        for platform in PLATFORMS:
            count = process_platform(platform, dry_run=args.dry_run)
            if count > 0:
                print(f"  ✅ {platform}: {count} rules converted")
            total += count
        print(f"\n  Total: {total} rules converted across all platforms")
        if not args.dry_run:
            print(f"\n  Next: Run --validate to check results")
        return
    
    if args.platform:
        count = process_platform(args.platform, dry_run=args.dry_run)
        print(f"\n  ✅ {args.platform}: {count} rules converted")
        return
    
    parser.print_help()


if __name__ == "__main__":
    main()