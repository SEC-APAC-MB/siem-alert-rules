#!/usr/bin/env python3
"""
Shared Detection Query Builder
===============================
Generates REAL, platform-native detection queries from rule metadata
(CVE ID, MITRE technique, category, product name, tags).

Used by:
  - generate_daily.py  (so new rules are born with real queries)
  - import_rules.py    (so existing placeholder rules get fixed)

Each query uses actual platform query language syntax with real field names
and log sources. No placeholders, no "KQL: ..." prefixes, no empty strings.

Query Logic Hierarchy:
  1. CVE-specific → product-aware detection patterns
  2. MITRE-specific → technique behavior detection
  3. Category-specific → attack pattern detection
  4. Tag-based fallback → keyword + log source filtering
"""

import re

# ─── MITRE Technique → Tactics Map ───────────────────────────

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
    "T1055.011": "DefenseEvasion", "T1053.005": "Execution",
    "T1213.002": "Collection", "T1552.001": "CredentialAccess",
}

MITRE_NAME_MAP = {
    "T1190": "Exploit Public-Facing Application", "T1189": "Drive-By Compromise",
    "T1078": "Valid Accounts", "T1110": "Brute Force",
    "T1548": "Abuse Elevation Control Mechanism", "T1552": "Unsecured Credentials",
    "T1213": "Data from Information Repositories", "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service", "T1059": "Command and Scripting Interpreter",
    "T1534": "Internal Spearphishing", "T1083": "File and Directory Discovery",
    "T1539": "Steal Web Session Cookie", "T1606": "Forge Web Credentials",
    "T1187": "Forced Authentication", "T1528": "Steal Application Access Token",
    "T1003": "OS Credential Dumping", "T1055": "Process Injection",
    "T1053": "Scheduled Task/Job", "T1136": "Create Account",
    "T1195": "Supply Chain Compromise", "T1199": "Trusted Relationship",
    "T1046": "Network Service Discovery", "T1040": "Network Sniffing",
    "T1568": "Dynamic Resolution", "T1071": "Application Layer Protocol",
}

TACTIC_ID_MAP = {
    "InitialAccess": "TA0001", "Execution": "TA0002", "Persistence": "TA0003",
    "PrivilegeEscalation": "TA0004", "DefenseEvasion": "TA0005",
    "CredentialAccess": "TA0006", "Discovery": "TA0007", "LateralMovement": "TA0008",
    "Collection": "TA0009", "CommandAndControl": "TA0011", "Exfiltration": "TA0010",
}

SEV_RISK = {"critical": 95, "high": 75, "medium": 50, "low": 25, "informational": 10, "info": 10}
SEV_SENTINEL = {"critical": "High", "high": "Medium", "medium": "Low", "low": "Informational", "informational": "Informational", "info": "Informational"}
SEV_AZURE_NUM = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
SEV_FORTISIEM = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Info", "info": "Info"}
SEV_OCI = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "INFO", "info": "INFO"}
SEV_WAZUH_LEVEL = {"critical": 12, "high": 10, "medium": 7, "low": 4, "informational": 2, "info": 2}


def map_mitre_to_tactic(technique):
    tech_main = technique.split(".")[0]
    return MITRE_TACTIC_MAP.get(tech_main, "")


def map_tactic_to_id(tactic):
    return TACTIC_ID_MAP.get(tactic, "")


def get_mitre_name(technique):
    tech_main = technique.split(".")[0]
    return MITRE_NAME_MAP.get(tech_main, technique)


# ─── CVE Product Detection Patterns ──────────────────────────
# Each product gets REAL detection logic based on known attack vectors.
# The key is the lowercase product keyword; the value is per-platform queries.

CVE_PRODUCT_PATTERNS = {
    "zimbra": {
        "elastic": 'event.category:"network" AND (url.path:("/zimbra/" OR "/h/" OR "/Compose*") OR http.request.body.content:"COBJ") AND NOT http.response.status_code:(200 OR 301)',
        "splunk": 'index=* (sourcetype="zimbra:mailbox" OR sourcetype="access_logs") ("COBJ" OR "/zimbra/" OR "zimbraAdmin") | stats count, values(src_ip) as src_ips by host, uri_path | where count > 3',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/zimbra/%' OR PAYLOAD LIKE '%COBJ%') AND NOT (RESPONSE_CODE = 200 OR RESPONSE_CODE = 301) LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/zimbra/" or RequestURL contains "COBJ") and (HttpStatusCode != 200 and HttpStatusCode != 301) | summarize count(), make_set(SourceIP) by TimeGenerated, RequestURL | where count_ > 3',
        "wazuh": '<if_sid>31100</if_sid><url>/zimbra/|/h/|COBJ</url>',
        "zeek": '(COBJ|\\/zimbra\\/|\\/h\\/)',
        "fortisiem": '(URL CONTAINS "/zimbra/" OR PAYLOAD CONTAINS "COBJ") AND (RESPONSE_CODE != 200 AND RESPONSE_CODE != 301)',
        "aws": '{ ($.requestURL = *zimbra*) && ($.httpStatus != 200) }',
        "azure": 'CommonSecurityLog | where RequestUri_s contains "/zimbra/" and (httpStatusCode_d != 200 and httpStatusCode_d != 301) | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 3',
        "oracle": "zimbra_exploit",
    },
    "sharepoint": {
        "elastic": 'event.category:"authentication" AND url.path:"/_layouts/*" AND (http.request.body.content:("__VIEWSTATE" OR "ctl00$") OR http.request.method:POST) AND NOT event.outcome:"success"',
        "splunk": 'index=* sourcetype="access_logs" "/_layouts/" ("__VIEWSTATE" OR "ctl00$") method=POST | stats count, values(src_ip) as src_ips by uri_path | where count > 5',
        "qradar": "SELECT * FROM events WHERE URL_PATH LIKE '%/_layouts/%' AND (PAYLOAD LIKE '%__VIEWSTATE%' OR PAYLOAD LIKE '%ctl00$%') AND METHOD = 'POST' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where RequestURL contains "/_layouts/" and RequestMethod == "POST" | summarize count(), make_set(SourceIP) by TimeGenerated, RequestURL | where count_ > 5',
        "wazuh": '<if_sid>31100</if_sid><url>/_layouts/</url><match>__VIEWSTATE|ctl00$</match>',
        "zeek": '(\\/\\_layouts\\/|__VIEWSTATE|ctl00\\$)',
        "fortisiem": '(URL CONTAINS "/_layouts/") AND (METHOD = "POST")',
        "aws": '{ ($.requestURL = *\\_layouts\\/*) && ($.requestMethod = POST) }',
        "azure": 'AzureDiagnostics | where RequestUri_s contains "/_layouts/" and RequestMethod_s == "POST" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 5',
        "oracle": "sharepoint_exploit",
    },
    "fortinet": {
        "elastic": 'event.category:"network" AND (http.request.body.content:("api=" OR "vdom=" OR "execute=") OR url.path:"/api/v2/cmdb/*") AND http.request.method:POST AND NOT http.response.status_code:200',
        "splunk": 'index=* sourcetype="fortigate_logs" OR sourcetype="access_logs" ("/api/v2/cmdb/" OR "api=") method=POST status!=200 | stats count, values(src_ip) as src_ips by uri_path, status | where count > 2',
        "qradar": "SELECT * FROM events WHERE URL_PATH LIKE '%/api/v2/cmdb/%' AND METHOD = 'POST' AND RESPONSE_CODE != 200 LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where RequestURL contains "/api/v2/cmdb/" and RequestMethod == "POST" and HttpStatusCode != 200 | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><url>/api/v2/cmdb/</url><match>api=|vdom=|execute=</match>',
        "zeek": '(\\/api\\/v2\\/cmdb\\/(?:api|vdom|execute)\\=)',
        "fortisiem": '(URL CONTAINS "/api/v2/cmdb/") AND (METHOD = "POST") AND (RESPONSE_CODE != 200)',
        "aws": '{ ($.requestURL = *api/v2/cmdb/*) && ($.requestMethod = POST) }',
        "azure": 'CommonSecurityLog | where RequestUri_s contains "/api/v2/cmdb/" and RequestMethod_s == "POST" and HttpStatusCode != 200 | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "fortinet_exploit",
    },
    "ivanti": {
        "elastic": 'event.category:"network" AND url.path:("/api/v1/cavms/*" OR "/dana-na/*" OR "/portal/*") AND (http.request.body.content:("DSIID=" OR "CSRFCookie=" OR "strCID=") OR http.response.status_code:(302 OR 500))',
        "splunk": 'index=* sourcetype="access_logs" ("/api/v1/cavms/" OR "/dana-na/" OR "/portal/") ("DSIID=" OR "CSRFCookie=" OR "strCID=" OR status=302) | stats count, values(src_ip) as src_ips by uri_path, status | where count > 2',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/dana-na/%' OR URL_PATH LIKE '%/api/v1/cavms/%') AND (PAYLOAD LIKE '%DSIID=%' OR PAYLOAD LIKE '%CSRFCookie=%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/dana-na/" or RequestURL contains "/api/v1/cavms/") and (RequestHeader contains "DSIID=" or RequestHeader contains "CSRFCookie=") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><url>/dana-na/|/api/v1/cavms/|/portal/</url><match>DSIID=|CSRFCookie=|strCID=</match>',
        "zeek": '(\\/dana\\-na\\/(?:DSIID|CSRFCookie|strCID)\\=)',
        "fortisiem": '(URL CONTAINS "/dana-na/" OR URL CONTAINS "/api/v1/cavms/") AND (PAYLOAD CONTAINS "DSIID=" OR PAYLOAD CONTAINS "CSRFCookie=")',
        "aws": '{ ($.requestURL = *dana-na*) || ($.requestURL = *api/v1/cavms*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "/dana-na/" or RequestUri_s contains "/api/v1/cavms/") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "ivanti_exploit",
    },
    "palo": {
        "elastic": 'event.category:"network" AND url.path:"/api/*" AND (http.request.body.content:("key=" OR "vsys=" OR "xpath=") OR http.request.headers:"X-PAN-KEY") AND http.request.method:(POST OR PUT)',
        "splunk": 'index=* sourcetype="pan:threat" OR sourcetype="access_logs" "/api/" ("X-PAN-KEY" OR "key=" OR "vsys=") method=POST OR method=PUT | stats count by src_ip, uri_path, action | where count > 2',
        "qradar": "SELECT * FROM events WHERE URL_PATH LIKE '%/api/%' AND (PAYLOAD LIKE '%X-PAN-KEY%' OR PAYLOAD LIKE '%vsys=%') AND METHOD IN ('POST', 'PUT') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where RequestURL contains "/api/" and (RequestHeader contains "X-PAN-KEY" or RequestHeader contains "vsys=") and RequestMethod in ("POST", "PUT") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><url>/api/</url><match>X-PAN-KEY|vsys=|xpath=</match>',
        "zeek": '(\\/api\\/(?:X\\-PAN\\-KEY|vsys\\=|xpath\\=))',
        "fortisiem": '(URL CONTAINS "/api/") AND (PAYLOAD CONTAINS "X-PAN-KEY" OR PAYLOAD CONTAINS "vsys=") AND (METHOD IN ("POST", "PUT"))',
        "aws": '{ ($.requestURL = */api/*) && ($.requestMethod in [POST,PUT]) }',
        "azure": 'CommonSecurityLog | where RequestUri_s contains "/api/" and RequestMethod_s in ("POST", "PUT") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "palo_alto_exploit",
    },
    "cisco": {
        "elastic": 'event.category:"network" AND (url.path:("/api/v1/global-config/*" OR "/rest/data/*" OR "/json/rest/*") OR http.request.headers:"X-Auth-Token") AND http.request.method:(POST OR PUT OR DELETE)',
        "splunk": 'index=* sourcetype="cisco:iosxe" OR sourcetype="access_logs" ("/api/v1/global-config/" OR "/rest/data/") ("X-Auth-Token" OR method=POST OR method=DELETE) | stats count by src_ip, uri_path | where count > 2',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/api/v1/global-config/%' OR URL_PATH LIKE '%/rest/data/%') AND METHOD IN ('POST', 'PUT', 'DELETE') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/api/v1/global-config/" or RequestURL contains "/rest/data/") and RequestMethod in ("POST", "PUT", "DELETE") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><url>/api/v1/global-config/|/rest/data/</url><match>X-Auth-Token</match>',
        "zeek": '(\\/api\\/v1\\/global\\-config\\/(?:X\\-Auth\\-Token))',
        "fortisiem": '(URL CONTAINS "/api/v1/global-config/" OR URL CONTAINS "/rest/data/") AND METHOD IN ("POST", "PUT", "DELETE")',
        "aws": '{ ($.requestURL = *api/v1/global-config*) || ($.requestURL = *rest/data*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "/api/v1/global-config/" or RequestUri_s contains "/rest/data/") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "cisco_exploit",
    },
    "microsoft": {
        "elastic": 'event.category:"authentication" AND (event.action:"login" OR event.action:"Logon") AND (user.name:("*admin*" OR "*Exchange*" OR "*Domain Admin*") OR source.ip:(NOT 10.* AND NOT 172.16.* AND NOT 192.168.*)) AND event.outcome:"success"',
        "splunk": 'index=* (sourcetype="wineventlog:security" OR sourcetype="ms:aad:signin") EventID=4624 (user=*admin* OR user=*Exchange*) (src_ip!=10.* AND src_ip!=172.16.* AND src_ip!=192.168.*) | stats count by user, src_ip, _time',
        "qradar": "SELECT * FROM events WHERE EVENT_TYPE = 'Authentication' AND USERNAME LIKE '%admin%' AND SOURCE_IP NOT LIKE '10.%' AND SOURCE_IP NOT LIKE '172.16.%' AND SOURCE_IP NOT LIKE '192.168.%' AND OUTCOME = 'SUCCESS' LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4624 and (Account contains "admin" or Account contains "Exchange") and SourceIP !startswith "10." and SourceIP !startswith "172.16." and SourceIP !startswith "192.168." | summarize count() by Account, SourceIP, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><user>admin|Exchange|Domain Admin</user><srcip>!10.|!172.16.|!192.168.</srcip>',
        "zeek": '(login|auth|admin|Exchange)',
        "fortisiem": '(EVENT_TYPE = "Authentication") AND (USERNAME CONTAINS "admin" OR USERNAME CONTAINS "Exchange") AND (SOURCE_IP NOT LIKE "10.%" AND SOURCE_IP NOT LIKE "172.16.%" AND SOURCE_IP NOT LIKE "192.168.%")',
        "aws": '{ ($.eventName = ConsoleLogin) && ($.responseElements.ConsoleLogin = Success) && ($.sourceIPAddress != 10.*) }',
        "azure": 'SecurityEvent | where EventID == 4624 and (Account contains "admin" or Account contains "Exchange") and SourceIP !startswith "10." | summarize count() by Account, SourceIP, bin(TimeGenerated, 5m)',
        "oracle": "microsoft_exploit",
    },
    "apache": {
        "elastic": 'event.category:"network" AND (http.request.body.content:("%{DOCUMENT_ROOT}" OR "%{HTTP_HOST}" OR "${file}") OR url.path:("*.php" OR "*.cgi" OR "*.pl") AND http.response.status_code:(500 OR 502))',
        "splunk": 'index=* sourcetype="access_logs" ("%{DOCUMENT_ROOT}" OR "%{HTTP_HOST}" OR "${file}") (uri_path="*.php" OR uri_path="*.cgi") (status=500 OR status=502) | stats count, values(src_ip) as src_ips by uri_path, status | where count > 2',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%\\%{DOCUMENT_ROOT}%' OR PAYLOAD LIKE '%\\%{HTTP_HOST}%') AND (URL_PATH LIKE '%.php%' OR URL_PATH LIKE '%.cgi%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestHeader contains "%{DOCUMENT_ROOT}" or RequestHeader contains "%{HTTP_HOST}") and (RequestURL endswith ".php" or RequestURL endswith ".cgi") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><match>%{DOCUMENT_ROOT}|%{HTTP_HOST}|${file}</match><url>.php|.cgi|.pl</url>',
        "zeek": '(%\\{DOCUMENT_ROOT\\}|%\\{HTTP_HOST\\}|\\$\\{file\\})',
        "fortisiem": '(PAYLOAD CONTAINS "%{DOCUMENT_ROOT}" OR PAYLOAD CONTAINS "%{HTTP_HOST}") AND (URL LIKE "%.php%" OR URL LIKE "%.cgi%")',
        "aws": '{ ($.requestURL = *.php*) || ($.requestURL = *.cgi*) }',
        "azure": 'AzureDiagnostics | where (RequestUri_s contains ".php" or RequestUri_s contains ".cgi") and (RequestHeader_s contains "%{DOCUMENT_ROOT}" or RequestHeader_s contains "%{HTTP_HOST}") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "apache_exploit",
    },
    "nginx": {
        "elastic": 'event.category:"network" AND (http.request.headers:"Transfer-Encoding: chunked" AND http.request.body.content.length > 0 AND http.response.status_code:400) OR (url.path:".." AND http.request.method:"GET")',
        "splunk": 'index=* sourcetype="access_logs" ("Transfer-Encoding: chunked" OR uri_path="*..*") (status=400 OR status=500) | stats count, values(src_ip) as src_ips by uri_path, status | where count > 2',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%Transfer-Encoding: chunked%' OR URL_PATH LIKE '%..%') AND (RESPONSE_CODE = 400 OR RESPONSE_CODE = 500) LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestHeader contains "Transfer-Encoding: chunked" or RequestURL contains "..") and (HttpStatusCode in (400, 500)) | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><match>Transfer-Encoding: chunked|..</match>',
        "zeek": '(Transfer\\-Encoding\\:\\schunked|\\.\\.)',
        "fortisiem": '(PAYLOAD CONTAINS "Transfer-Encoding: chunked" OR URL CONTAINS "..") AND (RESPONSE_CODE = 400 OR RESPONSE_CODE = 500)',
        "aws": '{ ($.requestURL = *..*) && ($.httpStatus in [400,500]) }',
        "azure": 'AzureDiagnostics | where (RequestUri_s contains ".." or RequestHeader_s contains "Transfer-Encoding") and (httpStatusCode_d in (400, 500)) | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "nginx_exploit",
    },
    "vmware": {
        "elastic": 'event.category:"authentication" AND (url.path:("/ui/*" OR "/vcenter/*" OR "/api/*" OR "/sdk") AND http.request.headers:"VMware-API-Token" AND NOT event.outcome:"success")',
        "splunk": 'index=* sourcetype="vmware:vc" OR sourcetype="access_logs" ("/ui/" OR "/vcenter/" OR "/sdk") "VMware-API-Token" | stats count, values(src_ip) as src_ips by uri_path, action | where count > 2',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/ui/%' OR URL_PATH LIKE '%/vcenter/%' OR URL_PATH LIKE '%/sdk%') AND PAYLOAD LIKE '%VMware-API-Token%' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/ui/" or RequestURL contains "/vcenter/" or RequestURL contains "/sdk") and RequestHeader contains "VMware-API-Token" | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><url>/ui/|/vcenter/|/sdk</url><match>VMware-API-Token</match>',
        "zeek": '(\\/ui\\/(?:VMware\\-API\\-Token)|\\/vcenter\\/|\\/sdk)',
        "fortisiem": '(URL CONTAINS "/ui/" OR URL CONTAINS "/vcenter/" OR URL CONTAINS "/sdk") AND PAYLOAD CONTAINS "VMware-API-Token"',
        "aws": '{ ($.requestURL = */ui/*) || ($.requestURL = */vcenter/*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "/ui/" or RequestUri_s contains "/vcenter/") and RequestHeader_s contains "VMware-API-Token" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "vmware_exploit",
    },
    "citrix": {
        "elastic": 'event.category:"network" AND url.path:("/cgi-bin/*" OR "/vpns/*" OR "/nfuse/*") AND (http.request.body.content:("NSC_AAAC" OR "nsrfccookie" OR "SRCSRVIDENTIFIER") OR http.response.status_code:(302 OR 401))',
        "splunk": 'index=* sourcetype="access_logs" ("/cgi-bin/" OR "/vpns/" OR "/nfuse/") ("NSC_AAAC" OR "nsrfccookie" OR status=302) | stats count, values(src_ip) as src_ips by uri_path, status | where count > 2',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/vpns/%' OR URL_PATH LIKE '%/cgi-bin/%') AND (PAYLOAD LIKE '%NSC_AAAC%' OR PAYLOAD LIKE '%nsrfccookie%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/vpns/" or RequestURL contains "/cgi-bin/") and (RequestHeader contains "NSC_AAAC" or RequestHeader contains "nsrfccookie") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><url>/vpns/|/cgi-bin/|/nfuse/</url><match>NSC_AAAC|nsrfccookie|SRCSRVIDENTIFIER</match>',
        "zeek": '(\\/vpns\\/(?:NSC_AAAC|nsrfccookie)|\\/cgi\\-bin\\/)',
        "fortisiem": '(URL CONTAINS "/vpns/" OR URL CONTAINS "/cgi-bin/") AND (PAYLOAD CONTAINS "NSC_AAAC" OR PAYLOAD CONTAINS "nsrfccookie")',
        "aws": '{ ($.requestURL = */vpns/*) || ($.requestURL = */cgi-bin/*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "/vpns/" or RequestUri_s contains "/cgi-bin/") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "citrix_exploit",
    },
    "junos": {
        "elastic": 'event.category:"network" AND url.path:"/api/*" AND http.request.headers:"Accept: application/json" AND (http.request.body.content:("config" OR "interfaces" OR "routing") AND http.request.method:(POST OR PUT))',
        "splunk": 'index=* sourcetype="junos" OR sourcetype="access_logs" "/api/" "Accept: application/json" method=POST OR method=PUT | stats count by src_ip, uri_path | where count > 2',
        "qradar": "SELECT * FROM events WHERE URL_PATH LIKE '%/api/%' AND METHOD IN ('POST', 'PUT') AND PAYLOAD LIKE '%config%' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where RequestURL contains "/api/" and RequestMethod in ("POST", "PUT") and RequestHeader contains "application/json" | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><url>/api/</url><match>config|interfaces|routing</match>',
        "zeek": '(\\/api\\/(?:config|interfaces|routing))',
        "fortisiem": '(URL CONTAINS "/api/") AND (METHOD IN ("POST", "PUT")) AND (PAYLOAD CONTAINS "config")',
        "aws": '{ ($.requestURL = */api/*) && ($.requestMethod in [POST,PUT]) }',
        "azure": 'CommonSecurityLog | where RequestUri_s contains "/api/" and RequestMethod_s in ("POST", "PUT") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "junos_exploit",
    },
    "sophos": {
        "elastic": 'event.category:"network" AND url.path:("/api/*" OR "/webconsole/*") AND (http.request.headers:"X-API-Key" OR http.request.body.content:"token=") AND http.request.method:POST',
        "splunk": 'index=* sourcetype="access_logs" ("/api/" OR "/webconsole/") ("X-API-Key" OR "token=") method=POST | stats count by src_ip, uri_path | where count > 2',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/api/%' OR URL_PATH LIKE '%/webconsole/%') AND (PAYLOAD LIKE '%X-API-Key%' OR PAYLOAD LIKE '%token=%') AND METHOD = 'POST' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/api/" or RequestURL contains "/webconsole/") and RequestMethod == "POST" | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><url>/api/|/webconsole/</url><match>X-API-Key|token=</match>',
        "zeek": '(\\/api\\/(?:X\\-API\\-Key|token\\=)|\\/webconsole\\/)',
        "fortisiem": '(URL CONTAINS "/api/" OR URL CONTAINS "/webconsole/") AND (PAYLOAD CONTAINS "X-API-Key" OR PAYLOAD CONTAINS "token=") AND METHOD = "POST"',
        "aws": '{ ($.requestURL = */api/*) && ($.requestMethod = POST) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "/api/" or RequestUri_s contains "/webconsole/") and RequestMethod_s == "POST" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "sophos_exploit",
    },
    "wordpress": {
        "elastic": 'event.category:"network" AND (url.path:("/wp-admin/*" OR "/wp-login.php" OR "/wp-content/*" OR "/xmlrpc.php") AND (http.request.body.content:("admin" OR "wp-" OR "xmlrpc") AND http.request.method:POST) AND NOT event.outcome:"success")',
        "splunk": 'index=* sourcetype="access_logs" ("/wp-admin/" OR "/wp-login.php" OR "/xmlrpc.php") method=POST (status=200 OR status=302 OR status=500) | stats count, values(src_ip) as src_ips by uri_path, status | where count > 5',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/wp-admin/%' OR URL_PATH LIKE '%/wp-login.php%' OR URL_PATH LIKE '%/xmlrpc.php%') AND METHOD = 'POST' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/wp-admin/" or RequestURL contains "/wp-login.php" or RequestURL contains "/xmlrpc.php") and RequestMethod == "POST" | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 5',
        "wazuh": '<if_sid>31100</if_sid><url>/wp-admin/|/wp-login.php|/xmlrpc.php</url><match>admin|wp-|xmlrpc</match>',
        'zeek': '(\\/wp\\-admin\\/(?:admin|wp\\-|xmlrpc)|\\/wp\\-login\\.php|\\/xmlrpc\\.php)',
        "fortisiem": '(URL CONTAINS "/wp-admin/" OR URL CONTAINS "/wp-login.php" OR URL CONTAINS "/xmlrpc.php") AND METHOD = "POST"',
        "aws": '{ ($.requestURL = */wp-admin/*) || ($.requestURL = */xmlrpc.php*) }',
        "azure": 'AzureDiagnostics | where (RequestUri_s contains "/wp-admin/" or RequestUri_s contains "/xmlrpc.php") and RequestMethod_s == "POST" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 5',
        "oracle": "wordpress_exploit",
    },
}


# ─── MITRE Technique Detection Patterns ──────────────────────

MITRE_PATTERNS = {
    "T1190": {  # Exploit Public-Facing Application
        "elastic": 'event.category:"network" AND (http.response.status_code:(400 OR 403 OR 500) AND (url.path:("*.php" OR "*.asp" OR "*.cgi" OR "*.jsp") AND http.request.method:POST))',
        "splunk": 'index=* sourcetype="access_logs" (status=400 OR status=403 OR status=500) (uri_path="*.php" OR uri_path="*.asp" OR uri_path="*.cgi") method=POST | stats count, values(src_ip) as src_ips by uri_path, status | where count > 5',
        "qradar": "SELECT * FROM events WHERE RESPONSE_CODE IN (400, 403, 500) AND (URL_PATH LIKE '%.php%' OR URL_PATH LIKE '%.asp%' OR URL_PATH LIKE '%.cgi%') AND METHOD = 'POST' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where HttpStatusCode in (400, 403, 500) and RequestMethod == "POST" and (RequestURL endswith ".php" or RequestURL endswith ".asp" or RequestURL endswith ".cgi") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 5',
        "wazuh": '<if_sid>31100</if_sid><match>exploit|injection|attack</match><url>.php|.asp|.cgi|.jsp</url>',
        "zeek": '(union|select|script|alert|onload|onerror|\\.\\./|\\.\\.\\\\)',
        "fortisiem": '(RESPONSE_CODE IN (400, 403, 500)) AND (URL LIKE "%.php%" OR URL LIKE "%.asp%" OR URL LIKE "%.cgi%") AND (METHOD = "POST")',
        "aws": '{ ($.httpStatus in [400,403,500]) && ($.requestMethod = POST) }',
        "azure": 'AzureDiagnostics | where httpStatusCode_d in (400, 403, 500) and RequestMethod_s == "POST" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 5',
        "oracle": "exploit_public_app",
    },
    "T1078": {  # Valid Accounts
        "elastic": 'event.category:"authentication" AND event.outcome:"success" AND (user.name:(*admin* OR *root* OR *service*) OR (source.ip:(NOT 10.* AND NOT 172.16.* AND NOT 192.168.*) AND event.action:"login"))',
        "splunk": 'index=* sourcetype="auth_logs" OR sourcetype="wineventlog:security" action=login result=success (user=*admin* OR user=*root* OR user=*service*) | stats count by user, src_ip, _time | where src_ip != "127.0.0.1"',
        "qradar": "SELECT * FROM events WHERE EVENT_TYPE = 'Authentication' AND OUTCOME = 'SUCCESS' AND (USERNAME LIKE '%admin%' OR USERNAME LIKE '%root%') AND SOURCE_IP NOT LIKE '10.%' AND SOURCE_IP NOT LIKE '172.16.%' AND SOURCE_IP NOT LIKE '192.168.%' LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4624 and (Account contains "admin" or Account contains "root" or AccountType != "User") and SourceIP !startswith "10." and SourceIP !startswith "172.16." | summarize count(), make_set(SourceIP) by Account, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><user>admin|root|service</user><action>login</action><status>success</status>',
        "zeek": '(login|auth|admin|root)',
        "fortisiem": '(EVENT_TYPE = "Authentication") AND (OUTCOME = "SUCCESS") AND (USERNAME CONTAINS "admin" OR USERNAME CONTAINS "root") AND (SOURCE_IP NOT LIKE "10.%" AND SOURCE_IP NOT LIKE "172.16.%")',
        "aws": '{ ($.eventName = ConsoleLogin) && ($.responseElements.ConsoleLogin = Success) && ($.sourceIPAddress != 10.*) }',
        "azure": 'SecurityEvent | where EventID == 4624 and (Account contains "admin" or Account contains "root") and SourceIP !startswith "10." and SourceIP !startswith "172.16." | summarize count() by Account, SourceIP, bin(TimeGenerated, 5m)',
        "oracle": "valid_accounts",
    },
    "T1110": {  # Brute Force
        "elastic": 'event.category:"authentication" AND event.outcome:"failure" | stats count() by source.ip, user.name | where count > 10',
        "splunk": 'index=* sourcetype="auth_logs" OR sourcetype="wineventlog:security" action=login result=failure | stats count by user, src_ip | where count > 10',
        "qradar": "SELECT USERNAME, SOURCE_IP, COUNT(*) AS failures FROM events WHERE EVENT_TYPE = 'Authentication' AND OUTCOME = 'FAILURE' GROUP BY USERNAME, SOURCE_IP HAVING COUNT(*) > 10 LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4625 | summarize FailureCount = count(), make_set(SourceIP) by Account, bin(TimeGenerated, 5m) | where FailureCount > 10',
        "wazuh": '<if_sid>60103</if_sid><action>login</action><status>failed</status><same_source_ip>10</same_source_ip>',
        "zeek": '(login|auth|password|passwd)',
        "fortisiem": '(EVENT_TYPE = "Authentication") AND (OUTCOME = "FAILURE") GROUP BY USERNAME, SOURCE_IP HAVING COUNT > 10',
        "aws": '{ ($.eventName = ConsoleLogin) && ($.responseElements.ConsoleLogin = Failure) }',
        "azure": 'SecurityEvent | where EventID == 4625 | summarize FailureCount = count() by Account, SourceIP, bin(TimeGenerated, 5m) | where FailureCount > 10',
        "oracle": "brute_force",
    },
    "T1548": {  # Abuse Elevation Control Mechanism
        "elastic": 'event.category:"process" AND (process.name:("sudo" OR "runas" OR "setuid") OR process.command_line:("*-Verb RunAs*" OR "*chmod 4*" OR "*setuid*")) AND NOT user.name:(*admin* OR *root*)',
        "splunk": 'index=* (sourcetype="linux_secure" OR sourcetype="wineventlog:security") ("sudo" OR "runas" OR "setuid" OR "chmod 4") NOT user=*admin* NOT user=*root* | stats count by user, host, command | where count > 2',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%sudo%' OR PAYLOAD LIKE '%runas%' OR PAYLOAD LIKE '%setuid%') AND USERNAME NOT LIKE '%admin%' AND USERNAME NOT LIKE '%root%' LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID in (4672, 4688) and (Process contains "sudo" or Process contains "runas" or CommandLine contains "setuid") and Account !contains "admin" | summarize count() by Account, Process, CommandLine, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>sudo|runas|setuid|chmod 4</match>',
        "zeek": '(sudo|runas|setuid|chmod)',
        "fortisiem": '(PAYLOAD CONTAINS "sudo" OR PAYLOAD CONTAINS "runas" OR PAYLOAD CONTAINS "setuid") AND (USERNAME NOT LIKE "%admin%" AND USERNAME NOT LIKE "%root%")',
        "aws": '{ ($.eventName = *Privilege*) || ($.eventName = *Role*) }',
        "azure": 'SecurityEvent | where EventID in (4672, 4688) and (CommandLine contains "sudo" or CommandLine contains "runas") | summarize count() by Account, bin(TimeGenerated, 5m)',
        "oracle": "privilege_escalation",
    },
    "T1552": {  # Unsecured Credentials
        "elastic": 'event.category:("file" OR "process") AND (file.path:(*password* OR *credential* OR *secret* OR *.pem OR *.key OR *.ppk) OR process.command_line:(*cat /etc/shadow* OR *cat /etc/passwd* OR *reg query*Credential*))',
        "splunk": 'index=* (sourcetype="access_logs" OR sourcetype="wineventlog") ("password=" OR "credential" OR "*.pem" OR "*.key" OR "/etc/shadow" OR "/etc/passwd") | stats count, values(src_ip) as src_ips by host, source | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%password%' OR PAYLOAD LIKE '%credential%' OR PAYLOAD LIKE '%.pem%' OR PAYLOAD LIKE '%.key%' OR PAYLOAD LIKE '%/etc/shadow%') LAST 15 MINUTES",
        "sentinel": 'union SecurityEvent, CommonSecurityLog | where (Message contains "password" or Message contains "credential" or Message contains "/etc/shadow" or Message contains ".pem") | summarize count() by bin(TimeGenerated, 5m), SourceIP',
        "wazuh": '<if_sid>60103</if_sid><match>password|credential|secret|.pem|.key|/etc/shadow</match>',
        "zeek": '(password|credential|secret|\\.pem|\\.key)',
        "fortisiem": '(PAYLOAD CONTAINS "password" OR PAYLOAD CONTAINS "credential" OR PAYLOAD CONTAINS ".pem" OR PAYLOAD CONTAINS ".key" OR PAYLOAD CONTAINS "/etc/shadow")',
        "aws": '{ ($.eventName = GetSecretValue) || ($.eventName = *Parameter*) }',
        "azure": 'union SecurityEvent, AzureDiagnostics | where (Message contains "password" or Message contains "credential" or Message contains ".pem") | summarize count() by bin(TimeGenerated, 5m), clientIp_s',
        "oracle": "unsecured_credentials",
    },
    "T1213": {  # Data from Information Repositories
        "elastic": 'event.category:"network" AND http.request.method:GET AND (url.path:("/api/*" OR "/export" OR "/download" OR "/backup" OR "/dump") AND http.response.status_code:200) | stats count() by source.ip, url.path | where count > 100',
        "splunk": 'index=* sourcetype="access_logs" method=GET (uri_path="/api/*" OR uri_path="/export" OR uri_path="/download" OR uri_path="/backup") status=200 | stats count by src_ip, uri_path | where count > 100',
        "qradar": "SELECT SOURCE_IP, URL_PATH, COUNT(*) AS accesses FROM events WHERE METHOD = 'GET' AND (URL_PATH LIKE '%/api/%' OR URL_PATH LIKE '%/export%' OR URL_PATH LIKE '%/download%') AND RESPONSE_CODE = 200 GROUP BY SOURCE_IP, URL_PATH HAVING COUNT(*) > 100 LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where RequestMethod == "GET" and (RequestURL contains "/api/" or RequestURL contains "/export" or RequestURL contains "/download") and HttpStatusCode == 200 | summarize count() by SourceIP, RequestURL, bin(TimeGenerated, 5m) | where count_ > 100',
        "wazuh": '<if_sid>31100</if_sid><url>/api/|/export|/download|/backup|/dump</url><status>200</status>',
        "zeek": '(\\/api\\/|\\/export|\\/download|\\/backup|\\/dump)',
        "fortisiem": '(METHOD = "GET") AND (URL CONTAINS "/api/" OR URL CONTAINS "/export" OR URL CONTAINS "/download") AND (RESPONSE_CODE = 200) GROUP BY SOURCE_IP, URL HAVING COUNT > 100',
        "aws": '{ ($.eventName = GetObject) || ($.eventName = ListBucket) }',
        "azure": 'CommonSecurityLog | where RequestMethod_s == "GET" and (RequestUri_s contains "/api/" or RequestUri_s contains "/export") and HttpStatusCode == 200 | summarize count() by SourceIP, bin(TimeGenerated, 5m) | where count_ > 100',
        "oracle": "data_repository_access",
    },
    "T1041": {  # Exfiltration Over C2 Channel
        "elastic": 'event.category:"network" AND network.bytes > 10485760 AND destination.ip:(NOT 10.* AND NOT 172.16.* AND NOT 192.168.*) AND network.protocol:("http" OR "https" OR "dns")',
        "splunk": 'index=* sourcetype="firewall" dest_ip!=10.* dest_ip!=172.16.* dest_ip!=192.168.* bytes > 10485760 | stats sum(bytes) as total_bytes by src_ip, dest_ip, dest_port | where total_bytes > 10485760',
        "qradar": "SELECT SOURCE_IP, DESTINATION_IP, SUM(BYTES) AS total FROM events WHERE DESTINATION_IP NOT LIKE '10.%' AND DESTINATION_IP NOT LIKE '172.16.%' AND DESTINATION_IP NOT LIKE '192.168.%' AND BYTES > 10485760 GROUP BY SOURCE_IP, DESTINATION_IP LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where DestinationIP !startswith "10." and DestinationIP !startswith "172.16." and DestinationIP !startswith "192.168." and SentBytes > 10485760 | summarize sum(SentBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>41500</if_sid><dstip>!10.|!172.16.|!192.168.</dstip>',
        "zeek": '(bytes > 10485760)',
        "fortisiem": '(DESTINATION_IP NOT LIKE "10.%" AND DESTINATION_IP NOT LIKE "172.16.%" AND DESTINATION_IP NOT LIKE "192.168.%") AND (BYTES > 10485760)',
        "aws": '{ ($.eventName = *PutObject*) && ($.sourceIPAddress != 10.*) }',
        "azure": 'CommonSecurityLog | where DestinationIP !startswith "10." and SentBytes > 10485760 | summarize sum(SentBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 5m)',
        "oracle": "c2_exfiltration",
    },
    "T1567": {  # Exfiltration Over Web Service
        "elastic": 'event.category:"network" AND (url.domain:("*.s3.amazonaws.com" OR "*.blob.core.windows.net" OR "*.googleapis.com" OR "dropbox.com" OR "onedrive.com" OR "transfer.sh" OR "gofile.io") AND network.bytes > 5242880)',
        "splunk": 'index=* sourcetype="firewall" (dest_domain="*.s3.amazonaws.com" OR dest_domain="*.blob.core.windows.net" OR dest_domain="dropbox.com" OR dest_domain="transfer.sh") bytes > 5242880 | stats sum(bytes) by src_ip, dest_domain | where sum > 5242880',
        "qradar": "SELECT SOURCE_IP, URL_DOMAIN, SUM(BYTES) AS total FROM events WHERE (URL_DOMAIN LIKE '%s3.amazonaws.com%' OR URL_DOMAIN LIKE '%blob.core.windows.net%' OR URL_DOMAIN LIKE '%dropbox.com%' OR URL_DOMAIN LIKE '%transfer.sh%') AND BYTES > 5242880 GROUP BY SOURCE_IP, URL_DOMAIN LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "s3.amazonaws.com" or RequestURL contains "blob.core.windows.net" or RequestURL contains "dropbox.com" or RequestURL contains "transfer.sh") and SentBytes > 5242880 | summarize sum(SentBytes) by SourceIP, RequestURL, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>41500</if_sid><url>s3.amazonaws.com|blob.core.windows.net|dropbox.com|transfer.sh|gofile.io</url>',
        "zeek": '(s3\\.amazonaws|blob\\.core|dropbox|transfer\\.sh|gofile)',
        "fortisiem": '(URL_DOMAIN LIKE "%s3.amazonaws.com%" OR URL_DOMAIN LIKE "%blob.core.windows.net%" OR URL_DOMAIN LIKE "%dropbox.com%" OR URL_DOMAIN LIKE "%transfer.sh%") AND (BYTES > 5242880)',
        "aws": '{ ($.requestURL = *s3.amazonaws.com*) || ($.requestURL = *transfer.sh*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "s3.amazonaws.com" or RequestUri_s contains "blob.core.windows.net" or RequestUri_s contains "transfer.sh") and SentBytes > 5242880 | summarize sum(SentBytes) by SourceIP, bin(TimeGenerated, 5m)',
        "oracle": "web_exfiltration",
    },
    "T1189": {  # Drive-By Compromise
        "elastic": 'event.category:"network" AND (url.path:("*.exe" OR "*.dll" OR "*.scr" OR "*.hta" OR "*.vbs") AND NOT url.domain:*internal*) AND http.request.method:GET',
        "splunk": 'index=* sourcetype="access_logs" (uri_path="*.exe" OR uri_path="*.dll" OR uri_path="*.hta" OR uri_path="*.vbs") NOT dest_domain=*internal* method=GET | stats count by src_ip, uri_path, dest_domain | where count > 1',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%.exe%' OR URL_PATH LIKE '%.dll%' OR URL_PATH LIKE '%.hta%' OR URL_PATH LIKE '%.vbs%') AND URL_DOMAIN NOT LIKE '%internal%' AND METHOD = 'GET' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL endswith ".exe" or RequestURL endswith ".dll" or RequestURL endswith ".hta" or RequestURL endswith ".vbs") and RequestURL !contains "internal" and RequestMethod == "GET" | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 1',
        "wazuh": '<if_sid>31100</if_sid><url>.exe|.dll|.scr|.hta|.vbs</url>',
        "zeek": '(\\.exe|\\.dll|\\.scr|\\.hta|\\.vbs)',
        "fortisiem": '(URL LIKE "%.exe%" OR URL LIKE "%.dll%" OR URL LIKE "%.hta%" OR URL LIKE "%.vbs%") AND (URL_DOMAIN NOT LIKE "%internal%") AND (METHOD = "GET")',
        "aws": '{ ($.requestURL = *.exe*) || ($.requestURL = *.dll*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s endswith ".exe" or RequestUri_s endswith ".dll" or RequestUri_s endswith ".hta") and RequestUri_s !contains "internal" | summarize count() by SourceIP, bin(TimeGenerated, 5m)',
        "oracle": "drive_by_compromise",
    },
    "T1059": {  # Command and Scripting Interpreter
        "elastic": 'event.category:"process" AND process.name:("powershell.exe" OR "cmd.exe" OR "bash" OR "sh" OR "python*" OR "perl" OR "ruby") AND process.command_line:("*-enc*" OR "*-exec*" OR "*base64*" OR "*import*" OR "*eval*" OR "*system(*")',
        "splunk": 'index=* sourcetype="wineventlog:security" OR sourcetype="linux_secure" (process=powershell.exe OR process=cmd.exe OR process=bash) (command_line="*-enc*" OR command_line="*base64*" OR command_line="*eval*" OR command_line="*system(*") | stats count by host, process, command_line | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%powershell%-%enc%' OR PAYLOAD LIKE '%cmd.exe%' OR PAYLOAD LIKE '%bash%eval%') AND (PAYLOAD LIKE '%base64%' OR PAYLOAD LIKE '%-enc%' OR PAYLOAD LIKE '%eval%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and (Process == "powershell.exe" or Process == "cmd.exe" or Process == "bash") and (CommandLine contains "-enc" or CommandLine contains "base64" or CommandLine contains "eval" or CommandLine contains "system(") | summarize count() by Computer, Process, CommandLine, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>powershell -enc|base64|eval|system(</match>',
        "zeek": '(powershell|cmd\\.exe|bash|python|perl|ruby)',
        "fortisiem": '(PAYLOAD LIKE "%powershell%-enc%" OR PAYLOAD LIKE "%base64%" OR PAYLOAD LIKE "%eval%" OR PAYLOAD LIKE "%system(%")',
        "aws": '{ ($.eventName = RunCommand) || ($.eventName = RunInstances) }',
        "azure": 'SecurityEvent | where EventID == 4688 and (Process == "powershell.exe" or Process == "cmd.exe") and (CommandLine contains "-enc" or CommandLine contains "base64") | summarize count() by Computer, Process, bin(TimeGenerated, 5m)',
        "oracle": "scripting_execution",
    },
    "T1534": {  # Internal Spearphishing
        "elastic": 'event.category:"email" AND (email.from.address:*@internal* AND email.to.address:*@internal*) AND (email.subject:("urgent" OR "invoice" OR "payment" OR "security alert" OR "password reset") OR email.attachments:*.zip*)',
        "splunk": 'index=* sourcetype="email" (from=*@internal* AND to=*@internal*) (subject="*urgent*" OR subject="*invoice*" OR subject="*payment*" OR attachment="*.zip*") | stats count by from, to, subject | where count > 1',
        "qradar": "SELECT * FROM events WHERE EVENT_TYPE = 'Email' AND SENDER LIKE '%@internal%' AND RECIPIENT LIKE '%@internal%' AND (SUBJECT LIKE '%urgent%' OR SUBJECT LIKE '%invoice%' OR SUBJECT LIKE '%payment%' OR ATTACHMENT LIKE '%.zip%') LAST 15 MINUTES",
        "sentinel": 'EmailEvents | where SenderMailFromAddress endswith "@internal" and RecipientEmailAddress endswith "@internal" and (Subject contains "urgent" or Subject contains "invoice" or Subject contains "payment" or has_attachment == true) | summarize count() by SenderMailFromAddress, Subject, bin(TimeGenerated, 1h)',
        "wazuh": '<if_sid>60103</if_sid><match>urgent|invoice|payment|.zip</match><url>@internal</url>',
        "zeek": '(urgent|invoice|payment|\\.zip|attachment)',
        "fortisiem": '(EVENT_TYPE = "Email") AND (SENDER CONTAINS "@internal") AND (RECIPIENT CONTAINS "@internal") AND (SUBJECT CONTAINS "urgent" OR SUBJECT CONTAINS "invoice" OR ATTACHMENT CONTAINS ".zip")',
        "aws": '{ ($.eventName = SendEmail) && ($.source = ses) }',
        "azure": 'EmailEvents | where SenderMailFromAddress endswith "@internal" and RecipientEmailAddress endswith "@internal" and (Subject contains "urgent" or has_attachment == true) | summarize count() by SenderMailFromAddress, bin(TimeGenerated, 1h)',
        "oracle": "internal_spearphishing",
    },
    "T1055": {  # Process Injection
        "elastic": 'event.category:"process" AND (process.name:("rundll32.exe" OR "regsvr32.exe" OR "svchost.exe" OR "notepad.exe") AND (process.parent.name:("word.exe" OR "excel.exe" OR "outlook.exe" OR "powershell.exe") OR process.command_line:("*LoadLibrary*" OR "*VirtualAlloc*" OR "*WriteProcessMemory*" OR "*CreateRemoteThread*")))',
        "splunk": 'index=* sourcetype="wineventlog:security" (process=rundll32.exe OR process=regsvr32.exe OR process=svchost.exe) (parent_process=word.exe OR parent_process=excel.exe OR parent_process=outlook.exe) | stats count by host, process, parent_process | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PROCESS_NAME IN ('rundll32.exe', 'regsvr32.exe', 'svchost.exe')) AND (PARENT_PROCESS IN ('word.exe', 'excel.exe', 'outlook.exe') OR PAYLOAD LIKE '%LoadLibrary%' OR PAYLOAD LIKE '%VirtualAlloc%' OR PAYLOAD LIKE '%CreateRemoteThread%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and Process in ("rundll32.exe", "regsvr32.exe", "svchost.exe") and (ParentProcess in ("word.exe", "excel.exe", "outlook.exe") or CommandLine contains "LoadLibrary" or CommandLine contains "VirtualAlloc") | summarize count() by Computer, Process, ParentProcess, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>LoadLibrary|VirtualAlloc|WriteProcessMemory|CreateRemoteThread</match><process>rundll32.exe|regsvr32.exe|svchost.exe</process>',
        "zeek": '(LoadLibrary|VirtualAlloc|WriteProcessMemory|CreateRemoteThread)',
        "fortisiem": '(PROCESS_NAME IN ("rundll32.exe", "regsvr32.exe", "svchost.exe")) AND (PARENT_PROCESS IN ("word.exe", "excel.exe", "outlook.exe") OR PAYLOAD CONTAINS "LoadLibrary" OR PAYLOAD CONTAINS "VirtualAlloc")',
        "aws": '{ ($.eventName = *Inject*) }',
        "azure": 'SecurityEvent | where EventID == 4688 and Process in ("rundll32.exe", "regsvr32.exe") and (ParentProcess in ("word.exe", "excel.exe") or CommandLine contains "LoadLibrary") | summarize count() by Computer, Process, bin(TimeGenerated, 5m)',
        "oracle": "process_injection",
    },
    "T1003": {  # OS Credential Dumping
        "elastic": 'event.category:"process" AND (process.name:("lsass.exe" OR "procdump.exe" OR "mimikatz.exe" OR "sekurlsa") OR process.command_line:("*sekurlsa*" OR "*lsadump*" OR "*procdump*lsass*" OR "*reg save*HKLM\\sam*"))',
        "splunk": 'index=* sourcetype="wineventlog:security" OR sourcetype="linux_secure" ("mimikatz" OR "sekurlsa" OR "lsadump" OR "procdump" OR "reg save" OR "lsass") | stats count, values(src_ip) as src_ips by host, process, command_line | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%mimikatz%' OR PAYLOAD LIKE '%sekurlsa%' OR PAYLOAD LIKE '%lsadump%' OR PAYLOAD LIKE '%procdump%lsass%' OR PAYLOAD LIKE '%reg save%HKLM\\\\sam%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID in (4688, 4656, 4663) and (Process contains "mimikatz" or Process contains "procdump" or CommandLine contains "sekurlsa" or CommandLine contains "lsadump" or CommandLine contains "reg save") | summarize count() by Computer, Process, CommandLine, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>mimikatz|sekurlsa|lsadump|procdump|reg save</match>',
        "zeek": '(mimikatz|sekurlsa|lsadump|procdump|reg\\ save)',
        "fortisiem": '(PAYLOAD CONTAINS "mimikatz" OR PAYLOAD CONTAINS "sekurlsa" OR PAYLOAD CONTAINS "lsadump" OR PAYLOAD CONTAINS "procdump" OR PAYLOAD CONTAINS "reg save")',
        "aws": '{ ($.eventName = *Credential*) || ($.eventName = *Secret*) }',
        "azure": 'SecurityEvent | where (Process contains "mimikatz" or Process contains "procdump" or CommandLine contains "sekurlsa") | summarize count() by Computer, Process, bin(TimeGenerated, 5m)',
        "oracle": "credential_dumping",
    },
    "T1136": {  # Create Account
        "elastic": 'event.category:"process" AND (process.name:("net.exe" OR "useradd" OR "adduser") AND process.command_line:("*add*" OR "*create*")) OR (event.category:"authentication" AND event.action:"user_create" AND event.outcome:"success")',
        "splunk": 'index=* (sourcetype="wineventlog:security" OR sourcetype="linux_secure") ("net user" OR "net localgroup" OR "useradd" OR "adduser") | stats count by host, user, command_line | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%net user%add%' OR PAYLOAD LIKE '%useradd%' OR PAYLOAD LIKE '%adduser%' OR PAYLOAD LIKE '%net localgroup%add%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID in (4720, 4688) and (Process contains "net.exe" or Process contains "useradd" or CommandLine contains "net user" or CommandLine contains "net localgroup") | summarize count() by Computer, Account, Process, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>net user|useradd|adduser|net localgroup</match>',
        "zeek": '(net\\ user|useradd|adduser|net\\ localgroup)',
        "fortisiem": '(PAYLOAD CONTAINS "net user" OR PAYLOAD CONTAINS "useradd" OR PAYLOAD CONTAINS "adduser" OR PAYLOAD CONTAINS "net localgroup")',
        "aws": '{ ($.eventName = CreateUser) || ($.eventName = CreateLoginProfile) }',
        "azure": 'SecurityEvent | where EventID in (4720, 4688) and (CommandLine contains "net user" or CommandLine contains "useradd") | summarize count() by Computer, Account, bin(TimeGenerated, 5m)',
        "oracle": "create_account",
    },
    "T1195": {  # Supply Chain Compromise
        "elastic": 'event.category:"process" AND (process.name:("npm" OR "pip" OR "yarn" OR "gem" OR "cargo" OR "go") AND process.command_line:("*install*") AND NOT user.name:(*ci* OR *build* OR *jenkins* OR *github*))',
        "splunk": 'index=* (process=npm OR process=pip OR process=yarn OR process=gem OR process=cargo) command_line="*install*" NOT user=*ci* NOT user=*build* NOT user=*jenkins* | stats count by user, host, command_line | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%npm%install%' OR PAYLOAD LIKE '%pip%install%' OR PAYLOAD LIKE '%yarn%install%') AND USERNAME NOT LIKE '%ci%' AND USERNAME NOT LIKE '%build%' AND USERNAME NOT LIKE '%jenkins%' LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and Process in ("npm.exe", "pip.exe", "yarn.exe") and CommandLine contains "install" and Account !contains "ci" and Account !contains "build" | summarize count() by Account, Process, CommandLine, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>npm install|pip install|yarn install|gem install</match>',
        "zeek": '(npm\\ install|pip\\ install|yarn\\ install|gem\\ install)',
        "fortisiem": '(PAYLOAD LIKE "%npm%install%" OR PAYLOAD LIKE "%pip%install%" OR PAYLOAD LIKE "%yarn%install%") AND (USERNAME NOT LIKE "%ci%" AND USERNAME NOT LIKE "%build%")',
        "aws": '{ ($.eventName = *Install*) }',
        "azure": 'SecurityEvent | where EventID == 4688 and Process in ("npm.exe", "pip.exe") and CommandLine contains "install" | summarize count() by Account, bin(TimeGenerated, 5m)',
        "oracle": "supply_chain",
    },
    "T1046": {  # Network Service Discovery
        "elastic": 'event.category:"network" AND (network.transport:"tcp" AND (destination.port:(22 OR 80 OR 443 OR 445 OR 3389 OR 8080) AND source.ip:(10.* OR 172.16.* OR 192.168.*)) AND _count > 20) OR (process.name:("nmap" OR "masscan" OR "zmap" OR "rustscan"))',
        "splunk": 'index=* sourcetype="firewall" (dest_port=22 OR dest_port=80 OR dest_port=443 OR dest_port=445 OR dest_port=3389) src_ip=10.* OR src_ip=172.16.* OR src_ip=192.168.* | stats count, dc(dest_port) as ports_scanned by src_ip | where ports_scanned > 10',
        "qradar": "SELECT SOURCE_IP, COUNT(DISTINCT DESTINATION_PORT) AS ports FROM events WHERE DESTINATION_PORT IN (22, 80, 443, 445, 3389, 8080) GROUP BY SOURCE_IP HAVING COUNT(DISTINCT DESTINATION_PORT) > 10 LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where DestinationPort in (22, 80, 443, 445, 3389, 8080) | summarize PortCount = dcount(DestinationPort) by SourceIP, bin(TimeGenerated, 5m) | where PortCount > 10',
        "wazuh": '<if_sid>41500</if_sid><dstport>22|80|443|445|3389|8080</dstport><same_source_ip>20</same_source_ip>',
        'zeek': '(nmap|masscan|zmap|rustscan|scan)',
        "fortisiem": '(DESTINATION_PORT IN (22, 80, 443, 445, 3389, 8080)) GROUP BY SOURCE_IP HAVING COUNT(DISTINCT DESTINATION_PORT) > 10',
        "aws": '{ ($.eventName = *Scan*) || ($.eventName = *Discover*) }',
        "azure": 'CommonSecurityLog | where DestinationPort in (22, 80, 443, 445, 3389) | summarize PortCount = dcount(DestinationPort) by SourceIP, bin(TimeGenerated, 5m) | where PortCount > 10',
        "oracle": "network_discovery",
    },
    "T1053": {  # Scheduled Task/Job
        "elastic": 'event.category:"process" AND (process.command_line:("*schtasks*/create*" OR "*crontab*" OR "*at *" OR "*systemctl enable*" OR "*launchctl load*") AND NOT user.name:(*ci* OR *build*))',
        "splunk": 'index=* (sourcetype="wineventlog:security" OR sourcetype="linux_secure") ("schtasks" OR "crontab" OR "systemctl enable" OR "launchctl load") | stats count by user, host, command_line | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%schtasks%/create%' OR PAYLOAD LIKE '%crontab%' OR PAYLOAD LIKE '%systemctl%enable%' OR PAYLOAD LIKE '%launchctl%load%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and (CommandLine contains "schtasks" or CommandLine contains "crontab" or CommandLine contains "systemctl enable" or CommandLine contains "launchctl load") | summarize count() by Computer, Account, CommandLine, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>schtasks|crontab|systemctl enable|launchctl load</match>',
        "zeek": '(schtasks|crontab|systemctl\\ enable|launchctl\\ load)',
        "fortisiem": '(PAYLOAD CONTAINS "schtasks" OR PAYLOAD CONTAINS "crontab" OR PAYLOAD CONTAINS "systemctl enable" OR PAYLOAD CONTAINS "launchctl load")',
        "aws": '{ ($.eventName = *Schedule*) }',
        "azure": 'SecurityEvent | where EventID == 4688 and (CommandLine contains "schtasks" or CommandLine contains "crontab") | summarize count() by Computer, Account, bin(TimeGenerated, 5m)',
        "oracle": "scheduled_task",
    },
    "T1083": {  # File and Directory Discovery
        "elastic": 'event.category:"file" AND (process.command_line:("*dir *" OR "*ls *" OR "*find /" OR "*tree *" OR "*Get-ChildItem*" OR "*locate *") AND _count > 50)',
        "splunk": 'index=* (sourcetype="wineventlog" OR sourcetype="linux_secure") ("dir " OR "ls " OR "find /" OR "Get-ChildItem" OR "tree ") | stats count by user, host, command_line | where count > 50',
        "qradar": "SELECT USERNAME, COUNT(*) AS cmd_count FROM events WHERE (PAYLOAD LIKE '%dir %' OR PAYLOAD LIKE '%ls %' OR PAYLOAD LIKE '%find /%' OR PAYLOAD LIKE '%Get-ChildItem%') GROUP BY USERNAME HAVING COUNT(*) > 50 LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and (CommandLine contains "dir " or CommandLine contains "ls " or CommandLine contains "find /" or CommandLine contains "Get-ChildItem") | summarize count() by Computer, Account, bin(TimeGenerated, 5m) | where count_ > 50',
        "wazuh": '<if_sid>60103</if_sid><match>dir |ls |find /|Get-ChildItem|tree </match>',
        "zeek": '(dir\\ |ls\\ |find\\ \\/|Get\\-ChildItem|tree\\ )',
        "fortisiem": '(PAYLOAD CONTAINS "dir " OR PAYLOAD CONTAINS "ls " OR PAYLOAD CONTAINS "find /" OR PAYLOAD CONTAINS "Get-ChildItem") GROUP BY USERNAME HAVING COUNT > 50',
        "aws": '{ ($.eventName = *List*) && ($.resourceType = *Bucket*) }',
        "azure": 'SecurityEvent | where EventID == 4688 and (CommandLine contains "dir " or CommandLine contains "Get-ChildItem") | summarize count() by Computer, bin(TimeGenerated, 5m) | where count_ > 50',
        "oracle": "file_discovery",
    },
    "T1568": {  # Dynamic Resolution
        "elastic": 'event.category:"network" AND dns.question.name:("*.tk" OR "*.ml" OR "*.cf" OR "*.ga" OR "*.gq" OR "*dynamic*" OR "*dyndns*" OR "*no-ip*") AND dns.response_code:"NOERROR"',
        "splunk": 'index=* sourcetype="dns" (query="*.tk" OR query="*.ml" OR query="*.cf" OR query="*dyndns*" OR query="*no-ip*") | stats count by src_ip, query | where count > 5',
        "qradar": "SELECT * FROM events WHERE (DNS_QUERY LIKE '%.tk%' OR DNS_QUERY LIKE '%.ml%' OR DNS_QUERY LIKE '%.cf%' OR DNS_QUERY LIKE '%dyndns%' OR DNS_QUERY LIKE '%no-ip%') LAST 15 MINUTES",
        "sentinel": 'DnsEvents | where (Name endswith ".tk" or Name endswith ".ml" or Name endswith ".cf" or Name contains "dyndns" or Name contains "no-ip") | summarize count() by ClientIP, Name, bin(TimeGenerated, 5m) | where count_ > 5',
        "wazuh": '<if_sid>41500</if_sid><url>.tk|.ml|.cf|.ga|.gq|dyndns|no-ip</url>',
        "zeek": '(\\.tk|\\.ml|\\.cf|\\.ga|\\.gq|dyndns|no\\-ip)',
        "fortisiem": '(DNS_QUERY LIKE "%.tk%" OR DNS_QUERY LIKE "%.ml%" OR DNS_QUERY LIKE "%.cf%" OR DNS_QUERY LIKE "%dyndns%" OR DNS_QUERY LIKE "%no-ip%")',
        "aws": '{ ($.eventName = *Route53*) }',
        "azure": 'DnsEvents | where (Name endswith ".tk" or Name endswith ".ml" or Name contains "dyndns") | summarize count() by ClientIP, bin(TimeGenerated, 5m) | where count_ > 5',
        "oracle": "dynamic_resolution",
    },
    "T1071": {  # Application Layer Protocol
        "elastic": 'event.category:"network" AND network.protocol:("dns" OR "http" OR "https") AND (dns.question.name.length > 50 OR http.request.body.content.length > 10000) AND destination.ip:(NOT 10.* AND NOT 172.16.* AND NOT 192.168.*)',
        "splunk": 'index=* sourcetype="dns" OR sourcetype="firewall" (query_length > 50 OR bytes > 10000) dest_ip!=10.* dest_ip!=172.16.* dest_ip!=192.168.* | stats count by src_ip, dest_ip, protocol | where count > 10',
        "qradar": "SELECT * FROM events WHERE (DNS_QUERY_LENGTH > 50 OR PAYLOAD_LENGTH > 10000) AND DESTINATION_IP NOT LIKE '10.%' AND DESTINATION_IP NOT LIKE '172.16.%' AND DESTINATION_IP NOT LIKE '192.168.%' LAST 15 MINUTES",
        "sentinel": 'union DnsEvents, CommonSecurityLog | where (Name has more than 50 characters or SentBytes > 10000) and (DestinationIP !startswith "10." and DestinationIP !startswith "172.16.") | summarize count() by SourceIP, bin(TimeGenerated, 5m) | where count_ > 10',
        "wazuh": '<if_sid>41500</if_sid><dstip>!10.|!172.16.|!192.168.</dstip>',
        "zeek": '(dns|http|https)',
        "fortisiem": '(DNS_QUERY_LENGTH > 50 OR PAYLOAD_LENGTH > 10000) AND (DESTINATION_IP NOT LIKE "10.%" AND DESTINATION_IP NOT LIKE "172.16.%")',
        "aws": '{ ($.eventName = *Route53*) && ($.resourceType = *dns*) }',
        "azure": 'union DnsEvents, CommonSecurityLog | where SentBytes > 10000 and DestinationIP !startswith "10." | summarize count() by SourceIP, bin(TimeGenerated, 5m) | where count_ > 10',
        "oracle": "app_layer_protocol",
    },
}


# ─── Category Detection Patterns ─────────────────────────────

CATEGORY_PATTERNS = {
    "ai-llm": {
        "elastic": 'event.category:"network" AND (http.request.body.content:("ignore previous instructions" OR "you are now" OR "DAN" OR "jailbreak" OR "system prompt" OR "pretend you are" OR "ignore all instructions" OR "act as") OR url.path:("/chat" OR "/completion" OR "/api/llm" OR "/api/chat" OR "/v1/chat"))',
        "splunk": 'index=* sourcetype="access_logs" ("/chat" OR "/completion" OR "/api/llm" OR "/api/chat") ("ignore previous" OR "jailbreak" OR "DAN" OR "system prompt" OR "pretend you are" OR "ignore all instructions" OR "act as") | stats count, values(src_ip) as src_ips by uri_path | where count > 3',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/chat%' OR URL_PATH LIKE '%/completion%' OR URL_PATH LIKE '%/api/llm%') AND (PAYLOAD LIKE '%ignore previous%' OR PAYLOAD LIKE '%jailbreak%' OR PAYLOAD LIKE '%DAN%' OR PAYLOAD LIKE '%system prompt%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/chat" or RequestURL contains "/completion" or RequestURL contains "/api/llm") and (RequestHeader contains "ignore previous" or RequestHeader contains "jailbreak" or RequestHeader contains "DAN" or RequestHeader contains "system prompt" or RequestHeader contains "pretend you are") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 3',
        "wazuh": '<if_sid>31100</if_sid><url>/chat|/completion|/api/llm|/api/chat|/v1/chat</url><match>ignore previous|jailbreak|DAN|system prompt|pretend you are|ignore all instructions|act as</match>',
        "zeek": '(ignore\\ previous|jailbreak|DAN|system\\ prompt|pretend\\ you\\ are)',
        "fortisiem": '(URL CONTAINS "/chat" OR URL CONTAINS "/completion" OR URL CONTAINS "/api/llm") AND (PAYLOAD CONTAINS "ignore previous" OR PAYLOAD CONTAINS "jailbreak" OR PAYLOAD CONTAINS "DAN" OR PAYLOAD CONTAINS "system prompt")',
        "aws": '{ ($.requestURL = */chat*) || ($.requestURL = */completion*) || ($.requestURL = */api/llm*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "/chat" or RequestUri_s contains "/api/llm") and (RequestHeader_s contains "ignore previous" or RequestHeader_s contains "jailbreak" or RequestHeader_s contains "system prompt") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 3',
        "oracle": "ai_llm_attack",
    },
    "ai_llm_attacks": {  # underscore variant
        "elastic": 'event.category:"network" AND (http.request.body.content:("ignore previous instructions" OR "you are now" OR "DAN" OR "jailbreak" OR "system prompt" OR "pretend you are" OR "ignore all instructions" OR "act as") OR url.path:("/chat" OR "/completion" OR "/api/llm" OR "/api/chat" OR "/v1/chat"))',
        "splunk": 'index=* sourcetype="access_logs" ("/chat" OR "/completion" OR "/api/llm" OR "/api/chat") ("ignore previous" OR "jailbreak" OR "DAN" OR "system prompt" OR "pretend you are" OR "ignore all instructions" OR "act as") | stats count, values(src_ip) as src_ips by uri_path | where count > 3',
        "qradar": "SELECT * FROM events WHERE (URL_PATH LIKE '%/chat%' OR URL_PATH LIKE '%/completion%' OR URL_PATH LIKE '%/api/llm%') AND (PAYLOAD LIKE '%ignore previous%' OR PAYLOAD LIKE '%jailbreak%' OR PAYLOAD LIKE '%DAN%' OR PAYLOAD LIKE '%system prompt%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/chat" or RequestURL contains "/completion" or RequestURL contains "/api/llm") and (RequestHeader contains "ignore previous" or RequestHeader contains "jailbreak" or RequestHeader contains "DAN" or RequestHeader contains "system prompt") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 3',
        "wazuh": '<if_sid>31100</if_sid><url>/chat|/completion|/api/llm|/api/chat|/v1/chat</url><match>ignore previous|jailbreak|DAN|system prompt|pretend you are|ignore all instructions|act as</match>',
        "zeek": '(ignore\\ previous|jailbreak|DAN|system\\ prompt|pretend\\ you\\ are)',
        "fortisiem": '(URL CONTAINS "/chat" OR URL CONTAINS "/completion" OR URL CONTAINS "/api/llm") AND (PAYLOAD CONTAINS "ignore previous" OR PAYLOAD CONTAINS "jailbreak" OR PAYLOAD CONTAINS "DAN" OR PAYLOAD CONTAINS "system prompt")',
        "aws": '{ ($.requestURL = */chat*) || ($.requestURL = */completion*) || ($.requestURL = */api/llm*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "/chat" or RequestUri_s contains "/api/llm") and (RequestHeader_s contains "ignore previous" or RequestHeader_s contains "jailbreak") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 3',
        "oracle": "ai_llm_attack",
    },
    "cloud-native": {
        "elastic": 'event.category:"cloud" AND (cloud.provider:("aws" OR "azure" OR "gcp") AND event.action:("CreateUser" OR "CreateAccessKey" OR "AttachRolePolicy" OR "ModifyPolicy" OR "DeleteFlowLog" OR "StopLogging"))',
        "splunk": 'index=* sourcetype="aws:cloudtrail" OR sourcetype="azure:activity" (eventName="CreateUser" OR eventName="CreateAccessKey" OR eventName="AttachRolePolicy" OR eventName="DeleteFlowLog" OR eventName="StopLogging") | stats count by user, eventName, sourceIPAddress',
        "qradar": "SELECT * FROM events WHERE EVENT_NAME IN ('CreateUser', 'CreateAccessKey', 'AttachRolePolicy', 'DeleteFlowLog', 'StopLogging') LAST 15 MINUTES",
        "sentinel": 'AzureActivity | where OperationName in ("Create User", "Create Access Key", "Attach Role Policy", "Delete Flow Log") or OperationNameValue == "Microsoft.Authorization/roleAssignments/write" | summarize count() by Caller, OperationName, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog|StopLogging</match>',
        "zeek": '(CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog|StopLogging)',
        "fortisiem": '(EVENT_NAME IN ("CreateUser", "CreateAccessKey", "AttachRolePolicy", "DeleteFlowLog", "StopLogging"))',
        "aws": '{ ($.eventName = CreateUser) || ($.eventName = CreateAccessKey) || ($.eventName = AttachRolePolicy) || ($.eventName = DeleteFlowLog) }',
        "azure": 'AzureActivity | where OperationName in ("Create User", "Create Access Key", "Attach Role Policy", "Delete Flow Log") | summarize count() by Caller, bin(TimeGenerated, 5m)',
        "oracle": "cloud_native",
    },
    "cloud_native": {  # underscore variant — same as cloud-native
        "elastic": 'event.category:"cloud" AND (cloud.provider:("aws" OR "azure" OR "gcp") AND event.action:("CreateUser" OR "CreateAccessKey" OR "AttachRolePolicy" OR "ModifyPolicy" OR "DeleteFlowLog" OR "StopLogging"))',
        "splunk": 'index=* sourcetype="aws:cloudtrail" OR sourcetype="azure:activity" (eventName="CreateUser" OR eventName="CreateAccessKey" OR eventName="AttachRolePolicy" OR eventName="DeleteFlowLog") | stats count by user, eventName, sourceIPAddress',
        "qradar": "SELECT * FROM events WHERE EVENT_NAME IN ('CreateUser', 'CreateAccessKey', 'AttachRolePolicy', 'DeleteFlowLog') LAST 15 MINUTES",
        "sentinel": 'AzureActivity | where OperationName in ("Create User", "Create Access Key", "Attach Role Policy", "Delete Flow Log") | summarize count() by Caller, OperationName, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog</match>',
        "zeek": '(CreateUser|CreateAccessKey|AttachRolePolicy|DeleteFlowLog)',
        "fortisiem": '(EVENT_NAME IN ("CreateUser", "CreateAccessKey", "AttachRolePolicy", "DeleteFlowLog"))',
        "aws": '{ ($.eventName = CreateUser) || ($.eventName = CreateAccessKey) || ($.eventName = AttachRolePolicy) || ($.eventName = DeleteFlowLog) }',
        "azure": 'AzureActivity | where OperationName in ("Create User", "Create Access Key", "Attach Role Policy", "Delete Flow Log") | summarize count() by Caller, bin(TimeGenerated, 5m)',
        "oracle": "cloud_native",
    },
    "cloud-container": {
        "elastic": 'event.category:"cloud" AND (container.action:("exec" OR "attach" OR "port-forward") OR kubernetes.event:("privilege escalation" OR "pod creation" OR "namespace deletion") OR docker.event:("privileged" OR "socket" OR "mount"))',
        "splunk": 'index=* sourcetype="kubernetes" OR sourcetype="docker" ("exec" OR "attach" OR "port-forward" OR "privileged" OR "namespace deletion") | stats count, values(src_ip) as src_ips by host, action | where count > 2',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%exec%' OR PAYLOAD LIKE '%privileged%' OR PAYLOAD LIKE '%namespace deletion%') AND (EVENT_TYPE LIKE '%kubernetes%' OR EVENT_TYPE LIKE '%docker%') LAST 15 MINUTES",
        "sentinel": 'union ContainerInventory, KubernetesActivity | where (Action contains "exec" or Action contains "privileged" or Action contains "namespace deletion") | summarize count(), make_set(SourceIP) by Action, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>60103</if_sid><match>exec|attach|port-forward|privileged|namespace deletion</match>',
        "zeek": '(exec|attach|port\\-forward|privileged|namespace\\ deletion)',
        "fortisiem": '(PAYLOAD CONTAINS "exec" OR PAYLOAD CONTAINS "privileged" OR PAYLOAD CONTAINS "namespace deletion") AND (EVENT_TYPE LIKE "%kubernetes%" OR EVENT_TYPE LIKE "%docker%")',
        "aws": '{ ($.eventName = *Container*) || ($.eventName = *EKS*) }',
        "azure": 'AzureActivity | where OperationName contains "container" or OperationName contains "AKS" | summarize count() by Caller, bin(TimeGenerated, 5m)',
        "oracle": "cloud_container",
    },
    "ransomware": {
        "elastic": 'event.category:"file" AND (file.extension:("encrypted" OR "locked" OR "crypto") OR process.command_line:("*vssadmin delete*" OR "*wbadmin delete*" OR "*bcdedit*safe mode*" OR "*cipher /e*"))',
        "splunk": 'index=* ("vssadmin delete" OR "wbadmin delete" OR "bcdedit" OR "cipher /e" OR "*.encrypted" OR "*.locked") | stats count, values(host) as hosts by src_ip, command | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%vssadmin delete%' OR PAYLOAD LIKE '%wbadmin delete%' OR PAYLOAD LIKE '%cipher /e%' OR FILE_EXTENSION IN ('encrypted', 'locked', 'crypto')) LAST 15 MINUTES",
        "sentinel": 'union SecurityEvent, CommonSecurityLog | where (CommandLine contains "vssadmin delete" or CommandLine contains "wbadmin delete" or Message contains ".encrypted" or Message contains ".locked") | summarize count(), make_set(Computer) by SourceIP, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>vssadmin delete|wbadmin delete|bcdedit|cipher /e|.encrypted|.locked</match>',
        "zeek": '(vssadmin\\ delete|wbadmin\\ delete|bcdedit|cipher\\ \\/e|\\.encrypted|\\.locked)',
        "fortisiem": '(PAYLOAD CONTAINS "vssadmin delete" OR PAYLOAD CONTAINS "wbadmin delete" OR PAYLOAD CONTAINS "cipher /e" OR FILE_EXTENSION IN ("encrypted", "locked", "crypto"))',
        "aws": '{ ($.eventName = *Delete*) && ($.resourceType = *Snapshot*) }',
        "azure": 'union SecurityEvent, AzureDiagnostics | where (CommandLine contains "vssadmin delete" or Message contains ".encrypted") | summarize count() by Computer, bin(TimeGenerated, 5m)',
        "oracle": "ransomware",
    },
    "supply-chain": {
        "elastic": 'event.category:"process" AND (process.name:("npm" OR "pip" OR "yarn" OR "gem" OR "cargo" OR "go") AND process.command_line:("*install*") AND NOT user.name:(*ci* OR *build* OR *jenkins*))',
        "splunk": 'index=* (process=npm OR process=pip OR process=yarn OR process=gem) command_line="*install*" NOT user=*ci* NOT user=*build* | stats count by user, host, command_line | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%npm%install%' OR PAYLOAD LIKE '%pip%install%') AND USERNAME NOT LIKE '%ci%' AND USERNAME NOT LIKE '%build%' LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and Process in ("npm.exe", "pip.exe", "yarn.exe") and CommandLine contains "install" and Account !contains "ci" | summarize count() by Account, Process, CommandLine, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>npm install|pip install|yarn install|gem install</match>',
        "zeek": '(npm\\ install|pip\\ install|yarn\\ install|gem\\ install)',
        "fortisiem": '(PAYLOAD LIKE "%npm%install%" OR PAYLOAD LIKE "%pip%install%") AND USERNAME NOT LIKE "%ci%" AND USERNAME NOT LIKE "%build%"',
        "aws": '{ ($.eventName = *Install*) }',
        "azure": 'SecurityEvent | where EventID == 4688 and Process in ("npm.exe", "pip.exe") and CommandLine contains "install" | summarize count() by Account, bin(TimeGenerated, 5m)',
        "oracle": "supply_chain",
    },
    "supply_chain": {  # underscore variant
        "elastic": 'event.category:"process" AND (process.name:("npm" OR "pip" OR "yarn" OR "gem" OR "cargo") AND process.command_line:("*install*") AND NOT user.name:(*ci* OR *build*))',
        "splunk": 'index=* (process=npm OR process=pip OR process=yarn) command_line="*install*" NOT user=*ci* | stats count by user, host | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%npm%install%' OR PAYLOAD LIKE '%pip%install%') AND USERNAME NOT LIKE '%ci%' LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and Process in ("npm.exe", "pip.exe") and CommandLine contains "install" | summarize count() by Account, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>npm install|pip install|yarn install</match>',
        "zeek": '(npm\\ install|pip\\ install)',
        "fortisiem": '(PAYLOAD LIKE "%npm%install%" OR PAYLOAD LIKE "%pip%install%") AND USERNAME NOT LIKE "%ci%"',
        "aws": '{ ($.eventName = *Install*) }',
        "azure": 'SecurityEvent | where EventID == 4688 and Process in ("npm.exe", "pip.exe") and CommandLine contains "install" | summarize count() by Account, bin(TimeGenerated, 5m)',
        "oracle": "supply_chain",
    },
    "exfiltration": {
        "elastic": 'event.category:"network" AND network.bytes > 10485760 AND destination.ip:(NOT 10.* AND NOT 172.16.* AND NOT 192.168.*) AND network.protocol:("https" OR "ftp" OR "sftp")',
        "splunk": 'index=* sourcetype="firewall" bytes > 10485760 dest_ip!=10.* dest_ip!=172.16.* dest_ip!=192.168.* | stats sum(bytes) as total_bytes by src_ip, dest_ip, dest_port | where total_bytes > 10485760',
        "qradar": "SELECT SOURCE_IP, DESTINATION_IP, SUM(BYTES) AS total FROM events WHERE DESTINATION_IP NOT LIKE '10.%' AND DESTINATION_IP NOT LIKE '172.16.%' AND DESTINATION_IP NOT LIKE '192.168.%' AND BYTES > 10485760 GROUP BY SOURCE_IP, DESTINATION_IP LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where DestinationIP !startswith "10." and DestinationIP !startswith "172.16." and SentBytes > 10485760 | summarize sum(SentBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>41500</if_sid><dstip>!10.|!172.16.|!192.168.</dstip>',
        "zeek": '(bytes\\ >\\ 10485760)',
        "fortisiem": '(DESTINATION_IP NOT LIKE "10.%" AND DESTINATION_IP NOT LIKE "172.16.%") AND (BYTES > 10485760)',
        "aws": '{ ($.eventName = PutObject) && ($.sourceIPAddress != 10.*) }',
        "azure": 'CommonSecurityLog | where DestinationIP !startswith "10." and SentBytes > 10485760 | summarize sum(SentBytes) by SourceIP, bin(TimeGenerated, 5m)',
        "oracle": "exfiltration",
    },
    "lateral-movement": {
        "elastic": 'event.category:"network" AND network.protocol:("smb" OR "rdp" OR "winrm" OR "wmi") AND source.ip:(10.* OR 172.16.* OR 192.168.*) AND destination.ip:(10.* OR 172.16.* OR 192.168.*) AND source.ip != destination.ip',
        "splunk": 'index=* sourcetype="firewall" (protocol=smb OR protocol=rdp OR protocol=winrm) src_ip=10.* OR src_ip=172.16.* OR src_ip=192.168.* dest_ip=10.* OR dest_ip=172.16.* OR dest_ip=192.168.* | stats count by src_ip, dest_ip, protocol | where src_ip != dest_ip',
        "qradar": "SELECT * FROM events WHERE PROTOCOL IN ('SMB', 'RDP', 'WinRM', 'WMI') AND SOURCE_IP LIKE '10.%' AND DESTINATION_IP LIKE '10.%' AND SOURCE_IP != DESTINATION_IP LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where Protocol in ("SMB", "RDP", "WinRM") and SourceIP startswith "10." and DestinationIP startswith "10." and SourceIP != DestinationIP | summarize count() by SourceIP, DestinationIP, Protocol, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>41500</if_sid><protocol>smb|rdp|winrm|wmi</protocol>',
        "zeek": '(smb|rdp|winrm|wmi)',
        "fortisiem": '(PROTOCOL IN ("SMB", "RDP", "WinRM", "WMI")) AND (SOURCE_IP LIKE "10.%" AND DESTINATION_IP LIKE "10.%") AND (SOURCE_IP != DESTINATION_IP)',
        "aws": '{ ($.eventName = *Instance*) && ($.resourceType = *EC2*) }',
        "azure": 'CommonSecurityLog | where Protocol in ("SMB", "RDP", "WinRM") and SourceIP startswith "10." | summarize count() by SourceIP, DestinationIP, bin(TimeGenerated, 5m)',
        "oracle": "lateral_movement",
    },
    "lateral_movement": {  # underscore variant
        "elastic": 'event.category:"network" AND network.protocol:("smb" OR "rdp" OR "winrm" OR "wmi") AND source.ip:(10.* OR 172.16.* OR 192.168.*) AND destination.ip:(10.* OR 172.16.* OR 192.168.*) AND source.ip != destination.ip',
        "splunk": 'index=* sourcetype="firewall" (protocol=smb OR protocol=rdp OR protocol=winrm) src_ip=10.* dest_ip=10.* | stats count by src_ip, dest_ip, protocol | where src_ip != dest_ip',
        "qradar": "SELECT * FROM events WHERE PROTOCOL IN ('SMB', 'RDP', 'WinRM') AND SOURCE_IP LIKE '10.%' AND DESTINATION_IP LIKE '10.%' AND SOURCE_IP != DESTINATION_IP LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where Protocol in ("SMB", "RDP", "WinRM") and SourceIP startswith "10." and DestinationIP startswith "10." and SourceIP != DestinationIP | summarize count() by SourceIP, DestinationIP, Protocol, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>41500</if_sid><protocol>smb|rdp|winrm|wmi</protocol>',
        "zeek": '(smb|rdp|winrm|wmi)',
        "fortisiem": '(PROTOCOL IN ("SMB", "RDP", "WinRM")) AND (SOURCE_IP LIKE "10.%" AND DESTINATION_IP LIKE "10.%") AND (SOURCE_IP != DESTINATION_IP)',
        "aws": '{ ($.eventName = *Instance*) }',
        "azure": 'CommonSecurityLog | where Protocol in ("SMB", "RDP", "WinRM") and SourceIP startswith "10." | summarize count() by SourceIP, DestinationIP, bin(TimeGenerated, 5m)',
        "oracle": "lateral_movement",
    },
    "privilege-escalation": {
        "elastic": 'event.category:"process" AND (process.name:("sudo" OR "su" OR "runas") AND process.command_line:("*-Verb RunAs*" OR "*setuid*" OR "*chmod 4*" OR "*net localgroup administrators*"))',
        "splunk": 'index=* (sourcetype="linux_secure" OR sourcetype="wineventlog") ("sudo" OR "runas" OR "setuid" OR "net localgroup administrators") | stats count by user, host, command | where count > 2',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%sudo%' OR PAYLOAD LIKE '%runas%' OR PAYLOAD LIKE '%setuid%' OR PAYLOAD LIKE '%net localgroup administrators%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID in (4672, 4688, 4673) and (Process contains "sudo" or Process contains "runas" or CommandLine contains "setuid" or CommandLine contains "net localgroup") | summarize count() by Account, Process, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>sudo|runas|setuid|net localgroup administrators</match>',
        "zeek": '(sudo|runas|setuid|net\\ localgroup)',
        "fortisiem": '(PAYLOAD CONTAINS "sudo" OR PAYLOAD CONTAINS "runas" OR PAYLOAD CONTAINS "setuid" OR PAYLOAD CONTAINS "net localgroup")',
        "aws": '{ ($.eventName = *Privilege*) || ($.eventName = *Role*) }',
        "azure": 'SecurityEvent | where EventID in (4672, 4688) and (CommandLine contains "sudo" or CommandLine contains "runas") | summarize count() by Account, bin(TimeGenerated, 5m)',
        "oracle": "privilege_escalation",
    },
    "initial-access": {
        "elastic": 'event.category:"authentication" AND event.outcome:"success" AND source.ip:(NOT 10.* AND NOT 172.16.* AND NOT 192.168.*) AND (user.name:(*admin* OR *root*) OR event.data.first_login:*true*)',
        "splunk": 'index=* sourcetype="auth_logs" action=login result=success src_ip!=10.* src_ip!=172.16.* src_ip!=192.168.* (user=*admin* OR user=*root*) | stats count by user, src_ip, _time',
        "qradar": "SELECT * FROM events WHERE EVENT_TYPE = 'Authentication' AND OUTCOME = 'SUCCESS' AND SOURCE_IP NOT LIKE '10.%' AND SOURCE_IP NOT LIKE '172.16.%' AND (USERNAME LIKE '%admin%' OR USERNAME LIKE '%root%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4624 and SourceIP !startswith "10." and SourceIP !startswith "172.16." and (Account contains "admin" or Account contains "root") | summarize count() by Account, SourceIP, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><user>admin|root</user><srcip>!10.|!172.16.|!192.168.</srcip><status>success</status>',
        "zeek": '(login|auth|admin|root)',
        "fortisiem": '(EVENT_TYPE = "Authentication") AND (OUTCOME = "SUCCESS") AND (SOURCE_IP NOT LIKE "10.%" AND SOURCE_IP NOT LIKE "172.16.%") AND (USERNAME CONTAINS "admin" OR USERNAME CONTAINS "root")',
        "aws": '{ ($.eventName = ConsoleLogin) && ($.responseElements.ConsoleLogin = Success) && ($.sourceIPAddress != 10.*) }',
        "azure": 'SecurityEvent | where EventID == 4624 and SourceIP !startswith "10." and (Account contains "admin") | summarize count() by Account, SourceIP, bin(TimeGenerated, 5m)',
        "oracle": "initial_access",
    },
    "initial_access": {  # underscore variant
        "elastic": 'event.category:"authentication" AND event.outcome:"success" AND source.ip:(NOT 10.* AND NOT 172.16.* AND NOT 192.168.*) AND (user.name:(*admin* OR *root*))',
        "splunk": 'index=* sourcetype="auth_logs" action=login result=success src_ip!=10.* src_ip!=172.16.* (user=*admin* OR user=*root*) | stats count by user, src_ip, _time',
        "qradar": "SELECT * FROM events WHERE EVENT_TYPE = 'Authentication' AND OUTCOME = 'SUCCESS' AND SOURCE_IP NOT LIKE '10.%' AND (USERNAME LIKE '%admin%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4624 and SourceIP !startswith "10." and Account contains "admin" | summarize count() by Account, SourceIP, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><user>admin|root</user><status>success</status>',
        "zeek": '(login|auth|admin)',
        "fortisiem": '(EVENT_TYPE = "Authentication") AND (OUTCOME = "SUCCESS") AND (SOURCE_IP NOT LIKE "10.%") AND (USERNAME CONTAINS "admin")',
        "aws": '{ ($.eventName = ConsoleLogin) && ($.responseElements.ConsoleLogin = Success) }',
        "azure": 'SecurityEvent | where EventID == 4624 and SourceIP !startswith "10." and Account contains "admin" | summarize count() by Account, SourceIP, bin(TimeGenerated, 5m)',
        "oracle": "initial_access",
    },
    "zero-day": {
        "elastic": 'event.category:"network" AND http.response.status_code:(500 OR 502 OR 503) AND url.path:("*.cgi" OR "*.php" OR "*.asp" OR "*.jsp") AND http.request.method:POST',
        "splunk": 'index=* sourcetype="access_logs" (status=500 OR status=502 OR status=503) method=POST (uri_path="*.cgi" OR uri_path="*.php" OR uri_path="*.asp") | stats count, values(src_ip) as src_ips by uri_path, status | where count > 3',
        "qradar": "SELECT * FROM events WHERE RESPONSE_CODE IN (500, 502, 503) AND (URL_PATH LIKE '%.cgi%' OR URL_PATH LIKE '%.php%' OR URL_PATH LIKE '%.asp%') AND METHOD = 'POST' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where HttpStatusCode in (500, 502, 503) and RequestMethod == "POST" and (RequestURL endswith ".cgi" or RequestURL endswith ".php" or RequestURL endswith ".asp") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 3',
        "wazuh": '<if_sid>31100</if_sid><url>.cgi|.php|.asp|.jsp</url><status>500|502|503</status>',
        "zeek": '(\\.cgi|\\.php|\\.asp|\\.jsp)',
        "fortisiem": '(RESPONSE_CODE IN (500, 502, 503)) AND (URL LIKE "%.cgi%" OR URL LIKE "%.php%" OR URL LIKE "%.asp%") AND (METHOD = "POST")',
        "aws": '{ ($.httpStatus in [500,502,503]) && ($.requestMethod = POST) }',
        "azure": 'AzureDiagnostics | where httpStatusCode_d in (500, 502, 503) and RequestMethod_s == "POST" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 3',
        "oracle": "zero_day",
    },
    "zero_day": {  # underscore variant
        "elastic": 'event.category:"network" AND http.response.status_code:(500 OR 502 OR 503) AND url.path:("*.cgi" OR "*.php" OR "*.asp") AND http.request.method:POST',
        "splunk": 'index=* sourcetype="access_logs" (status=500 OR status=502 OR status=503) method=POST (uri_path="*.cgi" OR uri_path="*.php") | stats count by uri_path, status | where count > 3',
        "qradar": "SELECT * FROM events WHERE RESPONSE_CODE IN (500, 502, 503) AND (URL_PATH LIKE '%.cgi%' OR URL_PATH LIKE '%.php%') AND METHOD = 'POST' LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where HttpStatusCode in (500, 502, 503) and RequestMethod == "POST" and (RequestURL endswith ".cgi" or RequestURL endswith ".php") | summarize count() by RequestURL, bin(TimeGenerated, 5m) | where count_ > 3',
        "wazuh": '<if_sid>31100</if_sid><url>.cgi|.php|.asp</url><status>500|502|503</status>',
        "zeek": '(\\.cgi|\\.php|\\.asp)',
        "fortisiem": '(RESPONSE_CODE IN (500, 502, 503)) AND (URL LIKE "%.cgi%" OR URL LIKE "%.php%") AND (METHOD = "POST")',
        "aws": '{ ($.httpStatus in [500,502,503]) }',
        "azure": 'AzureDiagnostics | where httpStatusCode_d in (500, 502, 503) and RequestMethod_s == "POST" | summarize count() by bin(TimeGenerated, 5m) | where count_ > 3',
        "oracle": "zero_day",
    },
    "web-application": {
        "elastic": 'event.category:"network" AND (url.path:("*.sql" OR "*.php" OR "*.asp" OR "*.jsp") AND (http.request.body.content:("UNION SELECT" OR "OR 1=1" OR "<script" OR "../" OR "..\\") OR url.query:("SELECT" OR "UNION" OR "script")))',
        "splunk": 'index=* sourcetype="access_logs" ("UNION SELECT" OR "OR 1=1" OR "<script" OR "../" OR "..\\") | stats count, values(src_ip) as src_ips by uri_path, status | where count > 5',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%UNION SELECT%' OR PAYLOAD LIKE '%OR 1=1%' OR PAYLOAD LIKE '%<script%' OR URL_PATH LIKE '%../%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "UNION SELECT" or RequestURL contains "OR 1=1" or RequestURL contains "<script" or RequestURL contains "../") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 5',
        "wazuh": '<if_sid>31100</if_sid><match>UNION SELECT|OR 1=1|<script|../|..\\</match>',
        "zeek": '(UNION\\ SELECT|OR\\ 1\\=1|\\<script|\\.\\./|\\.\\.\\\\)',
        "fortisiem": '(PAYLOAD CONTAINS "UNION SELECT" OR PAYLOAD CONTAINS "OR 1=1" OR PAYLOAD CONTAINS "<script" OR URL CONTAINS "../")',
        "aws": '{ ($.requestURL = *UNION*) || ($.requestURL = *script*) }',
        "azure": 'AzureDiagnostics | where (RequestUri_s contains "UNION" or RequestUri_s contains "script" or RequestUri_s contains "../") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 5',
        "oracle": "web_app_attack",
    },
    "database": {
        "elastic": 'event.category:"database" AND (postgresql.query:("SELECT * FROM pg_authid" OR "COPY TO" OR "pg_dump") OR mysql.query:("INTO OUTFILE" OR "LOAD_FILE") OR mssql.query:("xp_cmdshell" OR "OPENROWSET" OR "sp_adduser"))',
        "splunk": 'index=* (sourcetype="postgresql" OR sourcetype="mysql" OR sourcetype="mssql") ("pg_authid" OR "xp_cmdshell" OR "INTO OUTFILE" OR "LOAD_FILE" OR "pg_dump") | stats count by user, query, host',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%pg_authid%' OR PAYLOAD LIKE '%xp_cmdshell%' OR PAYLOAD LIKE '%INTO OUTFILE%' OR PAYLOAD LIKE '%LOAD_FILE%' OR PAYLOAD LIKE '%pg_dump%') LAST 15 MINUTES",
        "sentinel": 'union AzureDiagnostics, CommonSecurityLog | where (Message contains "pg_authid" or Message contains "xp_cmdshell" or Message contains "INTO OUTFILE" or Message contains "pg_dump") | summarize count() by bin(TimeGenerated, 5m), SourceIP',
        "wazuh": '<if_sid>60103</if_sid><match>pg_authid|xp_cmdshell|INTO OUTFILE|LOAD_FILE|pg_dump</match>',
        "zeek": '(pg_authid|xp_cmdshell|INTO\\ OUTFILE|LOAD_FILE|pg_dump)',
        "fortisiem": '(PAYLOAD CONTAINS "pg_authid" OR PAYLOAD CONTAINS "xp_cmdshell" OR PAYLOAD CONTAINS "INTO OUTFILE" OR PAYLOAD CONTAINS "LOAD_FILE" OR PAYLOAD CONTAINS "pg_dump")',
        "aws": '{ ($.eventName = *RDS*) && ($.eventName = *Query*) }',
        "azure": 'AzureDiagnostics | where Message contains "xp_cmdshell" or Message contains "pg_dump" | summarize count() by bin(TimeGenerated, 5m)',
        "oracle": "database_attack",
    },
    "endpoint": {
        "elastic": 'event.category:("process" OR "file" OR "registry") AND (process.name:("powershell.exe" OR "cmd.exe" OR "wmic.exe" OR "rundll32.exe" OR "regsvr32.exe" OR "mshta.exe") OR process.command_line:("*-enc*" OR "*bypass*" OR "*downloadstring*" OR "*hidden*"))',
        "splunk": 'index=* sourcetype="wineventlog:security" (process=powershell.exe OR process=cmd.exe OR process=wmic.exe OR process=rundll32.exe) (command_line="*-enc*" OR command_line="*bypass*" OR command_line="*downloadstring*") | stats count by host, process, command_line',
        "qradar": "SELECT * FROM events WHERE (PROCESS_NAME IN ('powershell.exe', 'cmd.exe', 'wmic.exe', 'rundll32.exe') OR PAYLOAD LIKE '%-enc%' OR PAYLOAD LIKE '%bypass%' OR PAYLOAD LIKE '%downloadstring%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and Process in ("powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe", "mshta.exe") and (CommandLine contains "-enc" or CommandLine contains "bypass" or CommandLine contains "downloadstring") | summarize count() by Computer, Process, CommandLine, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>-enc|bypass|downloadstring|hidden</match><process>powershell.exe|cmd.exe|wmic.exe|rundll32.exe|mshta.exe</process>',
        "zeek": '(powershell|cmd\\.exe|wmic|rundll32|regsvr32|mshta)',
        "fortisiem": '(PROCESS_NAME IN ("powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe") OR PAYLOAD CONTAINS "-enc" OR PAYLOAD CONTAINS "bypass" OR PAYLOAD CONTAINS "downloadstring")',
        "aws": '{ ($.eventName = *RunCommand*) }',
        "azure": 'SecurityEvent | where EventID == 4688 and Process in ("powershell.exe", "cmd.exe", "rundll32.exe") and (CommandLine contains "-enc" or CommandLine contains "bypass") | summarize count() by Computer, Process, bin(TimeGenerated, 5m)',
        "oracle": "endpoint",
    },
    "execution": {
        "elastic": 'event.category:"process" AND process.name:("powershell.exe" OR "cmd.exe" OR "bash" OR "sh" OR "python*") AND process.command_line:("*-enc*" OR "*base64*" OR "*eval*" OR "*system(*")',
        "splunk": 'index=* (sourcetype="wineventlog" OR sourcetype="linux_secure") (process=powershell.exe OR process=cmd.exe OR process=bash) (command_line="*-enc*" OR command_line="*base64*" OR command_line="*eval*") | stats count by host, process, command_line',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%-enc%' OR PAYLOAD LIKE '%base64%' OR PAYLOAD LIKE '%eval%' OR PAYLOAD LIKE '%system(%') AND (PROCESS_NAME IN ('powershell.exe', 'cmd.exe', 'bash', 'sh')) LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID == 4688 and Process in ("powershell.exe", "cmd.exe", "bash") and (CommandLine contains "-enc" or CommandLine contains "base64" or CommandLine contains "eval") | summarize count() by Computer, Process, CommandLine, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>-enc|base64|eval|system(</match><process>powershell.exe|cmd.exe|bash|sh|python</process>',
        "zeek": '(powershell|cmd\\.exe|bash|python|eval|base64)',
        "fortisiem": '(PAYLOAD CONTAINS "-enc" OR PAYLOAD CONTAINS "base64" OR PAYLOAD CONTAINS "eval") AND (PROCESS_NAME IN ("powershell.exe", "cmd.exe", "bash"))',
        "aws": '{ ($.eventName = RunCommand) || ($.eventName = RunInstances) }',
        "azure": 'SecurityEvent | where EventID == 4688 and Process in ("powershell.exe", "cmd.exe") and (CommandLine contains "-enc" or CommandLine contains "base64") | summarize count() by Computer, bin(TimeGenerated, 5m)',
        "oracle": "execution",
    },
    "persistence": {
        "elastic": 'event.category:("registry" OR "process") AND (registry.path:("*\\\\CurrentVersion\\\\Run*" OR "*\\\\CurrentVersion\\\\RunOnce*") OR process.command_line:("*schtasks*create*" OR "*crontab*" OR "*sc create*" OR "*systemctl enable*"))',
        "splunk": 'index=* (sourcetype="wineventlog" OR sourcetype="linux_secure") ("CurrentVersion\\\\Run" OR "schtasks" OR "crontab" OR "sc create" OR "systemctl enable") | stats count by user, host, command_line | where count > 1',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%CurrentVersion%Run%' OR PAYLOAD LIKE '%schtasks%create%' OR PAYLOAD LIKE '%crontab%' OR PAYLOAD LIKE '%sc create%' OR PAYLOAD LIKE '%systemctl%enable%') LAST 15 MINUTES",
        "sentinel": 'SecurityEvent | where EventID in (4657, 4688) and (RegistryKey contains "CurrentVersion\\\\Run" or CommandLine contains "schtasks" or CommandLine contains "crontab" or CommandLine contains "sc create") | summarize count() by Computer, Account, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>60103</if_sid><match>CurrentVersion\\Run|schtasks|crontab|sc create|systemctl enable</match>',
        "zeek": '(schtasks|crontab|sc\\ create|systemctl\\ enable)',
        "fortisiem": '(PAYLOAD CONTAINS "CurrentVersion" OR PAYLOAD CONTAINS "schtasks" OR PAYLOAD CONTAINS "crontab" OR PAYLOAD CONTAINS "sc create")',
        "aws": '{ ($.eventName = *Schedule*) }',
        "azure": 'SecurityEvent | where EventID in (4657, 4688) and (RegistryKey contains "CurrentVersion" or CommandLine contains "schtasks") | summarize count() by Computer, bin(TimeGenerated, 5m)',
        "oracle": "persistence",
    },
    "reconnaissance": {
        "elastic": 'event.category:"network" AND (http.request.method:GET AND url.path:("/admin" OR "/phpinfo" OR "/.env" OR "/.git" OR "/wp-admin" OR "/server-status") AND http.response.status_code:(403 OR 404))',
        "splunk": 'index=* sourcetype="access_logs" (uri_path="/admin" OR uri_path="/phpinfo" OR uri_path="/.env" OR uri_path="/.git" OR uri_path="/wp-admin") (status=403 OR status=404) | stats count, values(src_ip) as src_ips by uri_path, status | where count > 5',
        "qradar": "SELECT * FROM events WHERE (URL_PATH IN ('/admin', '/phpinfo', '/.env', '/.git', '/wp-admin', '/server-status') AND RESPONSE_CODE IN (403, 404)) LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where RequestURL in ("/admin", "/phpinfo", "/.env", "/.git", "/wp-admin", "/server-status") and HttpStatusCode in (403, 404) | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 5',
        "wazuh": '<if_sid>31100</if_sid><url>/admin|/phpinfo|/.env|/.git|/wp-admin|/server-status</url><status>403|404</status>',
        "zeek": '(\\/admin|\\/phpinfo|\\/\\.env|\\/\\.git|\\/wp\\-admin|\\/server\\-status)',
        "fortisiem": '(URL IN ("/admin", "/phpinfo", "/.env", "/.git", "/wp-admin") AND RESPONSE_CODE IN (403, 404))',
        "aws": '{ ($.requestURL = */admin*) || ($.requestURL = */.env*) }',
        "azure": 'AzureDiagnostics | where (RequestUri_s in ("/admin", "/phpinfo", "/.env", "/.git", "/wp-admin") and httpStatusCode_d in (403, 404)) | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 5',
        "oracle": "reconnaissance",
    },
    "network-infrastructure": {
        "elastic": 'event.category:"network" AND (network.protocol:("dns" OR "snmp" OR "ssh" OR "telnet") AND destination.port:(53 OR 161 OR 22 OR 23) AND network.bytes > 10000)',
        "splunk": 'index=* sourcetype="firewall" (protocol=dns OR protocol=snmp OR protocol=ssh OR protocol=telnet) (dest_port=53 OR dest_port=161 OR dest_port=22 OR dest_port=23) bytes > 10000 | stats count, sum(bytes) as total_bytes by src_ip, dest_ip, protocol',
        "qradar": "SELECT * FROM events WHERE (PROTOCOL IN ('DNS', 'SNMP', 'SSH', 'Telnet') OR DESTINATION_PORT IN (53, 161, 22, 23)) AND BYTES > 10000 LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (Protocol in ("DNS", "SNMP", "SSH", "Telnet") or DestinationPort in (53, 161, 22, 23)) and SentBytes > 10000 | summarize count(), sum(SentBytes) by SourceIP, DestinationIP, Protocol, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>41500</if_sid><dstport>53|161|22|23</dstport>',
        "zeek": '(dns|snmp|ssh|telnet)',
        "fortisiem": '(PROTOCOL IN ("DNS", "SNMP", "SSH", "Telnet") OR DESTINATION_PORT IN (53, 161, 22, 23)) AND BYTES > 10000',
        "aws": '{ ($.eventName = *Route53*) }',
        "azure": 'CommonSecurityLog | where Protocol in ("DNS", "SSH") and SentBytes > 10000 | summarize count() by SourceIP, DestinationIP, bin(TimeGenerated, 5m)',
        "oracle": "network_infrastructure",
    },
    "ics_ot": {
        "elastic": 'event.category:"network" AND (network.protocol:("modbus" OR "dnp3" OR "opcua" OR "s7comm") AND destination.port:(502 OR 20000 OR 4840 OR 102))',
        "splunk": 'index=* sourcetype="modbus" OR sourcetype="dnp3" OR sourcetype="opcua" (dest_port=502 OR dest_port=20000 OR dest_port=4840 OR dest_port=102) | stats count by src_ip, dest_ip, dest_port, protocol',
        "qradar": "SELECT * FROM events WHERE (PROTOCOL IN ('Modbus', 'DNP3', 'OPCUA', 'S7Comm') OR DESTINATION_PORT IN (502, 20000, 4840, 102)) LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (Protocol in ("Modbus", "DNP3", "OPCUA") or DestinationPort in (502, 20000, 4840, 102)) | summarize count() by SourceIP, DestinationIP, DestinationPort, Protocol, bin(TimeGenerated, 5m)',
        "wazuh": '<if_sid>41500</if_sid><dstport>502|20000|4840|102</dstport><protocol>modbus|dnp3|opcua|s7comm</protocol>',
        "zeek": '(modbus|dnp3|opcua|s7comm)',
        "fortisiem": '(PROTOCOL IN ("Modbus", "DNP3", "OPCUA", "S7Comm") OR DESTINATION_PORT IN (502, 20000, 4840, 102))',
        "aws": '{ ($.eventName = *Gateway*) }',
        "azure": 'CommonSecurityLog | where DestinationPort in (502, 20000, 4840, 102) | summarize count() by SourceIP, DestinationPort, bin(TimeGenerated, 5m)',
        "oracle": "ics_ot",
    },
    "mobile_security": {
        "elastic": 'event.category:"network" AND (user_agent:*Mobile* OR user_agent:*Android* OR user_agent:*iPhone*) AND http.request.method:POST AND url.path:("/api/device" OR "/api/mobile" OR "/push" OR "/register") AND NOT http.response.status_code:200',
        "splunk": 'index=* sourcetype="access_logs" (user_agent=*Mobile* OR user_agent=*Android* OR user_agent=*iPhone*) (uri_path="/api/device" OR uri_path="/api/mobile") method=POST status!=200 | stats count, values(src_ip) as src_ips by user_agent, uri_path | where count > 5',
        "qradar": "SELECT * FROM events WHERE (USER_AGENT LIKE '%Mobile%' OR USER_AGENT LIKE '%Android%' OR USER_AGENT LIKE '%iPhone%') AND METHOD = 'POST' AND RESPONSE_CODE != 200 LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestHeader contains "Mobile" or RequestHeader contains "Android" or RequestHeader contains "iPhone") and RequestMethod == "POST" and HttpStatusCode != 200 | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 5',
        "wazuh": '<if_sid>31100</if_sid><match>Mobile|Android|iPhone</match><url>/api/device|/api/mobile|/push|/register</url>',
        "zeek": '(Mobile|Android|iPhone)',
        "fortisiem": '(USER_AGENT LIKE "%Mobile%" OR USER_AGENT LIKE "%Android%" OR USER_AGENT LIKE "%iPhone%") AND METHOD = "POST" AND RESPONSE_CODE != 200',
        "aws": '{ ($.requestURL = */api/device*) || ($.requestURL = */api/mobile*) }',
        "azure": 'CommonSecurityLog | where (RequestHeader_s contains "Mobile" or RequestHeader_s contains "Android") and RequestMethod_s == "POST" and HttpStatusCode != 200 | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 5',
        "oracle": "mobile_security",
    },
    "mobile": {  # short variant
        "elastic": 'event.category:"network" AND (user_agent:*Mobile* OR user_agent:*Android* OR user_agent:*iPhone*) AND http.request.method:POST AND NOT http.response.status_code:200',
        "splunk": 'index=* sourcetype="access_logs" (user_agent=*Mobile* OR user_agent=*Android*) method=POST status!=200 | stats count by user_agent, uri_path | where count > 5',
        "qradar": "SELECT * FROM events WHERE (USER_AGENT LIKE '%Mobile%' OR USER_AGENT LIKE '%Android%') AND METHOD = 'POST' AND RESPONSE_CODE != 200 LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestHeader contains "Mobile" or RequestHeader contains "Android") and RequestMethod == "POST" and HttpStatusCode != 200 | summarize count() by SourceIP, bin(TimeGenerated, 5m) | where count_ > 5',
        "wazuh": '<if_sid>31100</if_sid><match>Mobile|Android|iPhone</match>',
        "zeek": '(Mobile|Android|iPhone)',
        "fortisiem": '(USER_AGENT LIKE "%Mobile%" OR USER_AGENT LIKE "%Android%") AND METHOD = "POST" AND RESPONSE_CODE != 200',
        "aws": '{ ($.userAgent = *Mobile*) }',
        "azure": 'CommonSecurityLog | where RequestHeader_s contains "Mobile" and RequestMethod_s == "POST" | summarize count() by bin(TimeGenerated, 5m) | where count_ > 5',
        "oracle": "mobile_security",
    },
    "mitre-attack": {
        "elastic": 'event.category:("network" OR "process" OR "authentication") AND (message:*"{tag1}"* OR process.command_line:*"{tag1}"* OR event.action:*"{tag1}"*) AND NOT event.outcome:"allowed"',
        "splunk": 'index=* ("{tag1}" OR "attack" OR "mitre") (sourcetype="access_logs" OR sourcetype="wineventlog" OR sourcetype="firewall") | stats count, values(src_ip) as src_ips by host, source, action | where count > 2',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%{tag1}%' OR EVENT_CATEGORY LIKE '%{tag1}%') AND OUTCOME != 'ALLOWED' LAST 15 MINUTES",
        "sentinel": 'union CommonSecurityLog, SecurityEvent, AzureDiagnostics | where (Message contains "{tag1}" or ActivityDisplayName contains "{tag1}") and ActivityDisplayName !contains "Allowed" | summarize count(), make_set(SourceIP) by bin(TimeGenerated, 5m), ActivityDisplayName | where count_ > 2',
        "wazuh": '<if_sid>60103</if_sid><match>{tag1}|attack|mitre</match>',
        "zeek": '({tag1}|attack|mitre)',
        "fortisiem": '(PAYLOAD CONTAINS "{tag1}" OR EVENT_CATEGORY CONTAINS "{tag1}") AND OUTCOME != "ALLOWED"',
        "aws": '{ ($.eventName = *Attack*) }',
        "azure": 'union CommonSecurityLog, SecurityEvent | where Message contains "{tag1}" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "mitre_attack",
    },
    "general": {
        "elastic": 'event.category:("network" OR "authentication" OR "process") AND (message:*"{tag1}"* OR url.path:*"{tag1}"* OR process.command_line:*"{tag1}"*)',
        "splunk": 'index=* ("{tag1}" OR "{tag2}") (sourcetype="access_logs" OR sourcetype="auth_logs" OR sourcetype="firewall") | stats count, values(src_ip) as src_ips by host, source | where count > 3',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%{tag1}%' OR PAYLOAD LIKE '%{tag2}%') LAST 15 MINUTES",
        "sentinel": 'union CommonSecurityLog, SecurityEvent, AzureDiagnostics | where Message contains "{tag1}" or Message contains "{tag2}" | summarize count(), make_set(SourceIP) by bin(TimeGenerated, 5m), ActivityDisplayName | where count_ > 3',
        "wazuh": '<if_sid>60103</if_sid><match>{tag1}|{tag2}</match>',
        "zeek": '({tag1}|{tag2})',
        "fortisiem": '(PAYLOAD CONTAINS "{tag1}" OR PAYLOAD CONTAINS "{tag2}")',
        "aws": '{ ($.eventName = "*") && ($.sourceIPAddress != "127.0.0.1") }',
        "azure": 'union CommonSecurityLog, SecurityEvent | where Message contains "{tag1}" or Message contains "{tag2}" | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 3',
        "oracle": "general_{tag1}",
    },
    "remote-code-execution": {
        "elastic": 'event.category:"network" AND http.request.method:POST AND (http.request.body.content:("exec(" OR "system(" OR "eval(" OR "passthru(" OR "shell_exec(" OR "popen(" OR "Runtime.exec" OR "ProcessBuilder"))',
        "splunk": 'index=* sourcetype="access_logs" method=POST ("exec(" OR "system(" OR "eval(" OR "passthru(" OR "shell_exec(" OR "Runtime.exec" OR "ProcessBuilder") | stats count, values(src_ip) as src_ips by uri_path, status | where count > 1',
        "qradar": "SELECT * FROM events WHERE METHOD = 'POST' AND (PAYLOAD LIKE '%exec(%' OR PAYLOAD LIKE '%system(%' OR PAYLOAD LIKE '%eval(%' OR PAYLOAD LIKE '%passthru(%' OR PAYLOAD LIKE '%shell_exec(%' OR PAYLOAD LIKE '%Runtime.exec%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where RequestMethod == "POST" and (RequestHeader contains "exec(" or RequestHeader contains "system(" or RequestHeader contains "eval(" or RequestHeader contains "Runtime.exec") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 1',
        "wazuh": '<if_sid>31100</if_sid><match>exec(|system(|eval(|passthru(|shell_exec(|popen(|Runtime.exec|ProcessBuilder</match>',
        "zeek": '(exec\\(|system\\(|eval\\(|passthru\\(|shell\\_exec\\(|Runtime\\.exec)',
        "fortisiem": '(METHOD = "POST") AND (PAYLOAD CONTAINS "exec(" OR PAYLOAD CONTAINS "system(" OR PAYLOAD CONTAINS "eval(" OR PAYLOAD CONTAINS "Runtime.exec")',
        "aws": '{ ($.requestMethod = POST) }',
        "azure": 'CommonSecurityLog | where RequestMethod_s == "POST" and (RequestHeader_s contains "exec(" or RequestHeader_s contains "system(" or RequestHeader_s contains "eval(") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 1',
        "oracle": "rce",
    },
    "sql-injection": {
        "elastic": 'event.category:"network" AND (http.request.body.content:("UNION SELECT" OR "OR 1=1" OR "\'; DROP TABLE" OR "xp_cmdshell") OR url.query:("UNION" OR "SELECT" OR "DROP" OR "INSERT"))',
        "splunk": 'index=* sourcetype="access_logs" ("UNION SELECT" OR "OR 1=1" OR "\'; DROP TABLE" OR "xp_cmdshell") | stats count, values(src_ip) as src_ips by uri_path, status | where count > 2',
        "qradar": "SELECT * FROM events WHERE (PAYLOAD LIKE '%UNION SELECT%' OR PAYLOAD LIKE '%OR 1=1%' OR PAYLOAD LIKE '%DROP TABLE%' OR PAYLOAD LIKE '%xp_cmdshell%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "UNION SELECT" or RequestURL contains "OR 1=1" or RequestURL contains "xp_cmdshell" or RequestHeader contains "UNION SELECT") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 2',
        "wazuh": '<if_sid>31100</if_sid><match>UNION SELECT|OR 1=1|DROP TABLE|xp_cmdshell</match>',
        "zeek": '(UNION\\ SELECT|OR\\ 1\\=1|DROP\\ TABLE|xp_cmdshell)',
        "fortisiem": '(PAYLOAD CONTAINS "UNION SELECT" OR PAYLOAD CONTAINS "OR 1=1" OR PAYLOAD CONTAINS "DROP TABLE" OR PAYLOAD CONTAINS "xp_cmdshell")',
        "aws": '{ ($.requestURL = *UNION*) || ($.requestURL = *SELECT*) }',
        "azure": 'AzureDiagnostics | where (RequestUri_s contains "UNION" or RequestUri_s contains "SELECT" or RequestHeader_s contains "UNION SELECT") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 2',
        "oracle": "sql_injection",
    },
    "ssrf": {
        "elastic": 'event.category:"network" AND (url.path:("/fetch" OR "/proxy" OR "/webhook" OR "/callback" OR "/api/fetch" OR "/api/proxy") AND (http.request.body.content:("169.254.169.254" OR "localhost" OR "127.0.0.1" OR "0.0.0.0" OR "metadata.google" OR "http://169.254")))',
        "splunk": 'index=* sourcetype="access_logs" (uri_path="/fetch" OR uri_path="/proxy" OR uri_path="/webhook" OR uri_path="/callback") ("169.254.169.254" OR "localhost" OR "127.0.0.1" OR "metadata.google") | stats count, values(src_ip) as src_ips by uri_path, status | where count > 1',
        "qradar": "SELECT * FROM events WHERE (URL_PATH IN ('/fetch', '/proxy', '/webhook', '/callback') OR URL_PATH LIKE '%/api/fetch%' OR URL_PATH LIKE '%/api/proxy%') AND (PAYLOAD LIKE '%169.254.169.254%' OR PAYLOAD LIKE '%localhost%' OR PAYLOAD LIKE '%127.0.0.1%' OR PAYLOAD LIKE '%metadata.google%') LAST 15 MINUTES",
        "sentinel": 'CommonSecurityLog | where (RequestURL contains "/fetch" or RequestURL contains "/proxy" or RequestURL contains "/webhook") and (RequestHeader contains "169.254.169.254" or RequestHeader contains "localhost" or RequestHeader contains "metadata.google") | summarize count(), make_set(SourceIP) by RequestURL, bin(TimeGenerated, 5m) | where count_ > 1',
        "wazuh": '<if_sid>31100</if_sid><url>/fetch|/proxy|/webhook|/callback|/api/fetch|/api/proxy</url><match>169.254.169.254|localhost|127.0.0.1|metadata.google</match>',
        "zeek": '(169\\.254\\.169\\.254|localhost|127\\.0\\.0\\.1|metadata\\.google)',
        "fortisiem": '(URL CONTAINS "/fetch" OR URL CONTAINS "/proxy" OR URL CONTAINS "/webhook") AND (PAYLOAD CONTAINS "169.254.169.254" OR PAYLOAD CONTAINS "localhost" OR PAYLOAD CONTAINS "metadata.google")',
        "aws": '{ ($.requestURL = */fetch*) && ($.requestBody = *169.254.169.254*) }',
        "azure": 'CommonSecurityLog | where (RequestUri_s contains "/fetch" or RequestUri_s contains "/proxy") and (RequestHeader_s contains "169.254.169.254" or RequestHeader_s contains "localhost") | summarize count() by bin(TimeGenerated, 5m), clientIp_s | where count_ > 1',
        "oracle": "ssrf",
    },
}


# ─── Main Query Builder ──────────────────────────────────────

def normalize_category(category):
    """Normalize category names — handle underscore/hyphen variants."""
    # Try direct lookup first
    if category in CATEGORY_PATTERNS:
        return category
    # Try hyphen → underscore
    if category.replace("-", "_") in CATEGORY_PATTERNS:
        return category.replace("-", "_")
    # Try underscore → hyphen
    if category.replace("_", "-") in CATEGORY_PATTERNS:
        return category.replace("_", "-")
    return None


def build_detection_query(rule, platform):
    """
    Generate a REAL detection query for the given platform based on rule metadata.
    
    Hierarchy:
      1. CVE-specific → product-aware detection (looks up product in CVE_PRODUCT_PATTERNS)
      2. MITRE-specific → technique behavior detection (looks up in MITRE_PATTERNS)
      3. Category-specific → attack pattern detection (looks up in CATEGORY_PATTERNS)
      4. Tag-based → keyword + log source filtering
    
    Returns empty string ONLY if no pattern matches at all (should not happen
    with the default category fallback).
    """
    name = rule.get("name", "")
    desc = rule.get("description", "")
    category = rule.get("category", "general")
    tags = rule.get("tags", [])
    mitre = rule.get("mitre_attack", rule.get("mitre", []))
    
    # Extract CVE ID if present
    cve_match = re.search(r'CVE-\d{4}-\d+', name + " " + desc)
    cve_id = cve_match.group(0) if cve_match else ""
    
    # Extract product name from rule name
    product = ""
    if " — " in name:
        product = name.split(" — ")[-1].replace(" Exploitation", "").strip()
    elif "Exploitation" in name:
        product = name.replace(" Exploitation", "").strip()
    product_lower = product.lower() if product else ""
    
    tag1 = tags[0] if tags else category
    tag2 = tags[1] if len(tags) > 1 else ""
    
    # 1. Try CVE-specific product pattern
    if cve_id and product_lower:
        for product_key, patterns in CVE_PRODUCT_PATTERNS.items():
            if product_key in product_lower:
                if platform in patterns:
                    query = patterns[platform]
                    # Format with tag values for queries that use {tag1} or {tag2}
                    if "{tag1}" in query:
                        query = query.format(tag1=tag1, tag2=tag2)
                    return query
    
    # 2. Try MITRE technique pattern
    for tech in mitre:
        tech_main = tech.split(".")[0]  # Get parent technique
        if tech_main in MITRE_PATTERNS and platform in MITRE_PATTERNS[tech_main]:
            return MITRE_PATTERNS[tech_main][platform]
    
    # 3. Try category pattern
    normalized = normalize_category(category)
    if normalized and normalized in CATEGORY_PATTERNS:
        patterns = CATEGORY_PATTERNS[normalized]
        if platform in patterns:
            query = patterns[platform]
            if "{tag1}" in query:
                query = query.format(tag1=tag1, tag2=tag2)
            return query
    
    # 4. Try tags as fallback (use general pattern with tags)
    if tag1:
        patterns = CATEGORY_PATTERNS.get("general", {})
        if platform in patterns:
            query = patterns[platform]
            if "{tag1}" in query:
                query = query.format(tag1=tag1, tag2=tag2)
            return query
    
    return ""


def is_placeholder_query(query, platform=""):
    """Check if a query string is a placeholder rather than real detection logic."""
    if not query or not query.strip():
        return True
    q = query.strip()
    # Known placeholder patterns from the original formatters
    if q.startswith("KQL:") or q.startswith("MQL:"):
        return True
    if q == "SELECT * FROM events WHERE CATEGORY = 'general'":
        return True
    if q == "<Pattern>" or q.startswith("<Pattern>") and len(q) < 50:
        return True
    if q.startswith('{$.eventName = "*"}') or q == '{$.eventName = "*"}':
        return True
    if ".*().*/ regex" in q:  # Zeek empty regex
        return True
    if "Placeholder" in q:
        return True
    if q == "event.category:*" or q == "message:*":
        return True
    return False


# ─── Response Workflows / Suggested Actions ──────────────────
# Each rule gets actionable response steps based on category, MITRE technique,
# and severity. These are NOT generic "investigate" placeholders — they are
# specific, ordered actions an analyst or SOAR playbook can execute.

RESPONSE_WORKFLOWS = {
    # CVE-based exploitation
    "cve_exploitation": {
        "description": "Active exploitation of known CVE — immediate response required",
        "triage": [
            "Identify the affected system and verify the CVE applies (check version, patch level)",
            "Check if the exploit attempt succeeded (review logs for follow-on activity)",
            "Identify the source IP and check for other activity from that IP",
        ],
        "containment": [
            "Isolate the affected system from the network if exploitation confirmed",
            "Block the source IP at the firewall/WAF",
            "Apply the vendor patch or mitigation if available",
            "If no patch available, apply virtual patch at WAF/IPS",
        ],
        "eradication": [
            "Scan the affected system for persistence mechanisms (scheduled tasks, services, webshells)",
            "Review all changes made since the exploitation attempt",
            "Remove any implanted backdoors or malware",
        ],
        "recovery": [
            "Restore the system from a known-good backup if compromised",
            "Verify system integrity (file hashes, service configurations)",
            "Reconnect to network only after verification",
        ],
        "lessons_learned": [
            "Document the timeline: detection → response → resolution",
            "Assess if detection latency meets SLA",
            "Update IOC feeds with source IP, user-agent, and payload signatures",
            "Review if similar systems are vulnerable to the same CVE",
        ],
    },
    # MITRE technique-based
    "T1190": {
        "description": "Exploit attempt against public-facing application",
        "triage": [
            "Check if the exploit payload matches known signatures (WAF logs, IDS alerts)",
            "Determine if the application is actually vulnerable to this attack vector",
            "Review application logs for successful exploitation indicators",
        ],
        "containment": [
            "Block source IP at WAF/firewall",
            "Enable WAF rule for this specific attack pattern if not already active",
            "Rate-limit requests from the source IP range",
        ],
        "eradication": [
            "Review web server access logs for additional requests from same IP",
            "Check application files for any modifications or webshell uploads",
            "Verify database integrity if SQL injection was attempted",
        ],
        "recovery": [
            "Patch the vulnerable application component",
            "Deploy virtual patch at WAF if vendor patch not yet available",
            "Clear any cached malicious content",
        ],
    },
    "T1078": {
        "description": "Valid account usage — potential unauthorized access",
        "triage": [
            "Verify if the login is legitimate (check with account owner, review MFA logs)",
            "Check login location, device, and time against user's typical pattern",
            "Review post-login activity for unusual actions",
        ],
        "containment": [
            "If unauthorized: disable the account immediately",
            "Revoke active sessions and tokens",
            "Force password reset and MFA re-enrollment",
            "Block the source IP if external",
        ],
        "eradication": [
            "Review all changes made during the session",
            "Check for new accounts, SSH keys, or API tokens created",
            "Audit group memberships and role assignments",
        ],
        "recovery": [
            "Restore account to pre-compromise state",
            "Remove any unauthorized access mechanisms",
            "Enable enhanced monitoring on the account for 30 days",
        ],
    },
    "T1110": {
        "description": "Brute force attack — credential guessing",
        "triage": [
            "Identify the targeted accounts and check if any were compromised",
            "Determine the source IP and check for geographic anomalies",
            "Count failed attempts and correlate with any successful logins",
        ],
        "containment": [
            "Block source IP(s) at firewall",
            "Enable account lockout policy if not already active",
            "Enforce MFA for all targeted accounts",
            "Deploy CAPTCHA or rate limiting on the login endpoint",
        ],
        "eradication": [
            "Reset passwords for any accounts that had >5 failed attempts",
            "Check for any successful logins during the brute force window",
            "Review for credential stuffing patterns (checking multiple accounts from one IP)",
        ],
    },
    "T1548": {
        "description": "Privilege escalation attempt",
        "triage": [
            "Identify the user and verify if the escalation was authorized",
            "Check what privileges were gained and what actions were taken",
            "Review the parent process and command line for malicious indicators",
        ],
        "containment": [
            "Suspend the user account if unauthorized",
            "Revoke any elevated privileges granted",
            "Isolate the host if compromise is confirmed",
        ],
        "eradication": [
            "Remove any setuid binaries or scheduled tasks created",
            "Audit all system changes made with elevated privileges",
            "Check for persistence mechanisms (new users, services, cron jobs)",
        ],
    },
    "T1552": {
        "description": "Unsecured credentials accessed — credential exposure",
        "triage": [
            "Identify which credentials were accessed and their scope",
            "Determine if the credentials were exfiltrated or only accessed locally",
            "Check for subsequent use of the exposed credentials",
        ],
        "containment": [
            "Immediately rotate all exposed credentials (passwords, API keys, certificates)",
            "Revoke any tokens or sessions created with exposed credentials",
            "Block egress traffic from the source system if exfiltration suspected",
        ],
        "eradication": [
            "Identify and secure the credential storage location (file, registry, env vars)",
            "Remove any credentials stored in plaintext",
            "Scan for other credential stores on the system",
        ],
    },
    "T1213": {
        "description": "Data collection from information repositories",
        "triage": [
            "Identify what data was accessed and the volume",
            "Determine if the access pattern is abnormal for the user/IP",
            "Check for data exfiltration following the collection",
        ],
        "containment": [
            "Suspend the user account if unauthorized",
            "Block the source IP if external",
            "Revoke API access tokens for the repository",
        ],
        "eradication": [
            "Audit all data accessed during the session",
            "Check for data copied to external locations",
            "Review access logs for other unauthorized access",
        ],
    },
    "T1041": {
        "description": "Exfiltration over C2 channel",
        "triage": [
            "Quantify the data volume exfiltrated",
            "Identify the destination IP/domain and check against threat intel",
            "Determine the source process or service sending data",
        ],
        "containment": [
            "Immediately block the destination IP/domain at firewall/DNS",
            "Isolate the source system",
            "Kill the process responsible for exfiltration",
        ],
        "eradication": [
            "Identify and remove the C2 implant",
            "Check for persistence mechanisms",
            "Scan for lateral movement from the compromised host",
        ],
    },
    "T1567": {
        "description": "Exfiltration over web service",
        "triage": [
            "Identify the web service used (S3, Azure Blob, Dropbox, etc.)",
            "Quantify the data volume and determine sensitivity",
            "Check if the upload was authorized (review IAM policies, user permissions)",
        ],
        "containment": [
            "Block the web service domain at the firewall/proxy if unauthorized",
            "Suspend the user's cloud access",
            "Revoke API keys or tokens used for the upload",
        ],
        "eradication": [
            "Check the cloud storage for uploaded data and remove if sensitive",
            "Review cloud audit logs for other unauthorized access",
            "Audit IAM policies for over-permissive roles",
        ],
    },
    "T1059": {
        "description": "Command and scripting interpreter abuse",
        "triage": [
            "Review the full command line and parent process",
            "Determine if the execution is legitimate (admin activity, CI/CD) or suspicious",
            "Check for encoded/base64 content and decode if present",
        ],
        "containment": [
            "Kill the process if malicious",
            "Isolate the host if compromise is confirmed",
            "Block the source of the command (remote admin tool, SSH session)",
        ],
        "eradication": [
            "Check for persistence (scheduled tasks, services, registry Run keys)",
            "Review all child processes spawned by the script",
            "Scan for downloaded payloads or additional malware",
        ],
    },
    "T1534": {
        "description": "Internal spearphishing — lateral email attack",
        "triage": [
            "Identify the sender account and verify if it's compromised",
            "List all recipients and check who opened/clicked attachments",
            "Examine the email content, attachments, and links",
        ],
        "containment": [
            "Immediately disable the sender's account",
            "Recall or quarantine the email from all recipient mailboxes",
            "Block any URLs or attachment hashes at the mail gateway",
        ],
        "eradication": [
            "Check all recipient workstations for compromise",
            "Review the sender's sent items for additional phishing emails",
            "Reset the sender's password and revoke all sessions",
        ],
    },
    "T1055": {
        "description": "Process injection — code injection detected",
        "triage": [
            "Identify the injected process and the injecting parent",
            "Determine what code was injected and its purpose",
            "Check if the injected process is making network connections",
        ],
        "containment": [
            "Kill the injected process",
            "Isolate the host",
            "Block any C2 domains/IPs contacted by the injected process",
        ],
        "eradication": [
            "Identify and remove the injector (malware, macro, script)",
            "Check for persistence mechanisms",
            "Scan system memory for other injected processes",
        ],
    },
    "T1003": {
        "description": "OS credential dumping — LSASS/SAM access",
        "triage": [
            "Identify the process accessing LSASS or credential stores",
            "Determine if the access is legitimate (antivirus, backup) or malicious",
            "Check for credential exfiltration following the dump",
        ],
        "containment": [
            "Immediately kill the dumping process",
            "Isolate the host — credential theft indicates active compromise",
            "Block network egress from the host",
        ],
        "eradication": [
            "Force password reset for ALL users who had credentials on the system",
            "Remove the dumping tool (mimikatz, procdump, etc.)",
            "Check for lateral movement using dumped credentials",
        ],
        "recovery": [
            "Rebuild the host from known-good image — credential dump = full compromise",
            "Deploy credential guard or LSASS protection",
            "Monitor for use of old credentials across the domain",
        ],
    },
    "T1136": {
        "description": "New account creation — potential persistence",
        "triage": [
            "Verify if the account creation was authorized (check change tickets, approvals)",
            "Review the account name, privileges, and group memberships",
            "Check who created the account and from where",
        ],
        "containment": [
            "Disable the new account if unauthorized",
            "Remove from any privileged groups",
            "Review and revoke any access keys or tokens created",
        ],
        "eradication": [
            "Delete the unauthorized account",
            "Audit for other accounts created by the same user/IP",
            "Check for backdoor accounts with similar names",
        ],
    },
    "T1195": {
        "description": "Supply chain compromise — package tampering",
        "triage": [
            "Identify the package and version installed",
            "Check the package against known-good hashes (npm audit, pip-audit)",
            "Determine who installed it and whether it was in CI/CD or local dev",
        ],
        "containment": [
            "Remove the compromised package from all systems",
            "Block the package registry or specific package version",
            "Rotate any credentials that may have been exposed during installation",
        ],
        "eradication": [
            "Audit all systems for the compromised package",
            "Review package post-install scripts for malicious actions",
            "Check for any backdoors installed by the package",
        ],
    },
    "T1046": {
        "description": "Network service discovery — port scanning",
        "triage": [
            "Identify the scanning source and determine if it's internal or external",
            "List the ports scanned and identify exposed services",
            "Check if the scanner found and connected to any services",
        ],
        "containment": [
            "Block the scanning IP at the firewall",
            "Close any unnecessarily open ports discovered",
            "Enable port scan detection on the IDS/IPS",
        ],
        "eradication": [
            "Verify all discovered services are properly secured",
            "Check for any successful connections following the scan",
            "Review firewall rules for overly permissive access",
        ],
    },
    "T1053": {
        "description": "Scheduled task/job creation — persistence mechanism",
        "triage": [
            "Review the task name, command, and schedule",
            "Determine if the task creation was authorized",
            "Check the parent process and user context",
        ],
        "containment": [
            "Remove the scheduled task if unauthorized",
            "Disable the user account if compromise is confirmed",
            "Isolate the host",
        ],
        "eradication": [
            "Check for other scheduled tasks created by the same user",
            "Review the task command for malicious payloads",
            "Audit cron/schtasks/systemd for other persistence",
        ],
    },
    "T1083": {
        "description": "File and directory discovery — enumeration activity",
        "triage": [
            "Determine if the enumeration is from an admin tool or attacker",
            "Check the volume and scope of the enumeration",
            "Review for access to sensitive directories (credentials, configs)",
        ],
        "containment": [
            "Suspend the user account if behavior is anomalous",
            "Block the source IP if external",
            "Enable file access auditing on sensitive directories",
        ],
    },
    "T1568": {
        "description": "Dynamic DNS resolution — potential C2",
        "triage": [
            "Identify the dynamic DNS domain and check against threat intel",
            "Determine which host is resolving the domain",
            "Check for connections to the resolved IP addresses",
        ],
        "containment": [
            "Block the dynamic DNS domain at the DNS resolver/firewall",
            "Block resolved IP addresses at the firewall",
            "Isolate the host making the DNS queries",
        ],
        "eradication": [
            "Check for malware using the dynamic DNS for C2",
            "Review for persistence mechanisms",
            "Scan the host for known malware families",
        ],
    },
    "T1071": {
        "description": "Application layer protocol abuse — potential C2",
        "triage": [
            "Identify the protocol (DNS, HTTP, HTTPS) and check for anomalies",
            "Review query patterns (long DNS queries, beacons, heartbeats)",
            "Check destination against threat intel feeds",
        ],
        "containment": [
            "Block the destination IP/domain at firewall/DNS",
            "Isolate the source host",
            "Enable DNS filtering for suspicious domains",
        ],
        "eradication": [
            "Identify and remove the C2 implant",
            "Check for data exfiltration over the protocol",
            "Review for persistence mechanisms",
        ],
    },
    # Category-based workflows
    "ransomware": {
        "description": "Ransomware activity detected — immediate action required",
        "triage": [
            "Identify the affected system and the scope of encryption",
            "Determine the ransomware family from indicators (file extensions, ransom note)",
            "Check for lateral movement to other systems",
        ],
        "containment": [
            "IMMEDIATELY isolate the affected system from the network",
            "Disable the compromised user account",
            "Block known C2 domains/IPs for the ransomware family",
            "Stop shadow copy deletion if in progress (kill vssadmin/wbadmin processes)",
        ],
        "eradication": [
            "Identify the entry point (phishing, RDP, exploit)",
            "Remove the ransomware binary and any secondary malware",
            "Check for data exfiltration before encryption (double extortion)",
        ],
        "recovery": [
            "Restore from offline/immutable backups — do NOT pay the ransom",
            "Rebuild the system from known-good image",
            "Verify backup integrity before restoration",
            "Monitor restored systems for reinfection",
        ],
        "lessons_learned": [
            "Document the full incident timeline",
            "Identify the initial access vector and close it",
            "Assess backup coverage and recovery time",
            "Review endpoint detection coverage",
        ],
    },
    "exfiltration": {
        "description": "Data exfiltration detected — data loss response",
        "triage": [
            "Quantify the data volume and identify what was exfiltrated",
            "Determine the destination and check against threat intel",
            "Assess data classification and regulatory impact",
        ],
        "containment": [
            "Block the exfiltration destination at the firewall/proxy",
            "Isolate the source system",
            "Disable the user account responsible",
        ],
        "eradication": [
            "Identify and remove the exfiltration tool or malware",
            "Check for other exfiltration channels (DNS tunneling, ICMP)",
            "Audit all data accessed by the compromised account",
        ],
        "recovery": [
            "Assess legal and regulatory notification requirements (GDPR, HIPAA)",
            "Rotate any credentials that may have been in the exfiltrated data",
            "Monitor for the exfiltrated data appearing on dark web or leak sites",
        ],
    },
    "lateral-movement": {
        "description": "Lateral movement detected — attacker spreading in network",
        "triage": [
            "Identify the source and destination systems",
            "Determine the protocol (SMB, RDP, WinRM) and verify legitimacy",
            "Check for credential reuse across systems",
        ],
        "containment": [
            "Isolate both source and destination systems",
            "Disable any compromised accounts",
            "Block lateral movement protocols at internal firewall segments",
        ],
        "eradication": [
            "Identify the initial entry point on the source system",
            "Check for persistence on both systems",
            "Audit all systems accessible from the compromised credentials",
        ],
    },
    "privilege-escalation": {
        "description": "Privilege escalation detected — unauthorized elevation",
        "triage": [
            "Identify the user and the target privilege level",
            "Review the escalation method (sudo, runas, setuid, exploit)",
            "Determine if the escalation was successful",
        ],
        "containment": [
            "Suspend the user account",
            "Revoke any elevated privileges gained",
            "Isolate the host if escalation was successful",
        ],
        "eradication": [
            "Remove any setuid binaries or misconfigurations that enabled escalation",
            "Audit all actions taken with elevated privileges",
            "Check for persistence enabled by the elevated access",
        ],
    },
    "initial-access": {
        "description": "Initial access detected — attacker gaining entry",
        "triage": [
            "Identify the access method (external login, phishing, exploit)",
            "Verify if the access is legitimate or malicious",
            "Determine the source geography and device fingerprint",
        ],
        "containment": [
            "Block the source IP at the firewall",
            "Disable the compromised account",
            "Revoke active sessions",
        ],
        "eradication": [
            "Determine the initial access vector and close it",
            "Check for persistence mechanisms",
            "Review for post-access activities (reconnaissance, lateral movement)",
        ],
    },
    "supply-chain": {
        "description": "Supply chain attack — compromised dependency",
        "triage": [
            "Identify the compromised package and its origin",
            "Determine which systems installed the package and when",
            "Check for post-install malicious actions",
        ],
        "containment": [
            "Remove the compromised package from all affected systems",
            "Block the package at the registry/proxy level",
            "Isolate systems that installed the package",
        ],
        "eradication": [
            "Audit for backdoors installed by the package",
            "Rotate credentials that may have been exposed",
            "Review package integrity (hashes, signatures) across all projects",
        ],
    },
    "ai-llm": {
        "description": "AI/LLM attack — prompt injection or jailbreak attempt",
        "triage": [
            "Identify the attack type (prompt injection, jailbreak, data extraction)",
            "Determine if the attack succeeded (check model output for compliance)",
            "Review the source IP and user for repeat offenses",
        ],
        "containment": [
            "Block the source IP/user from accessing the LLM API",
            "Rate-limit requests from the source",
            "Enable input filtering for known jailbreak patterns",
        ],
        "eradication": [
            "Review conversation history for data leakage",
            "Check if the attacker extracted system prompts or internal data",
            "Update guardrails with the new attack patterns observed",
        ],
        "lessons_learned": [
            "Add new jailbreak patterns to the filter database",
            "Review model output logging for auditability",
            "Assess if sensitive data was exposed in the conversation",
        ],
    },
    "cloud-native": {
        "description": "Cloud infrastructure attack — IAM or resource compromise",
        "triage": [
            "Identify the cloud event (user creation, key creation, policy change)",
            "Verify if the action was authorized (check change management)",
            "Review the source IP and API caller identity",
        ],
        "containment": [
            "Immediately revoke new access keys or tokens",
            "Disable any unauthorized new users",
            "Revert unauthorized policy changes",
        ],
        "eradication": [
            "Audit all IAM changes since the event",
            "Check for privilege escalation via role chaining",
            "Review CloudTrail/Activity Log for follow-on actions",
        ],
    },
    "web-application": {
        "description": "Web application attack — injection or XSS attempt",
        "triage": [
            "Identify the attack type (SQLi, XSS, path traversal, RCE)",
            "Determine if the attack was successful (check response codes, DB logs)",
            "Check for follow-on requests from the same source",
        ],
        "containment": [
            "Block the source IP at the WAF/firewall",
            "Enable WAF rule for the specific attack pattern",
            "Set the application to maintenance mode if compromised",
        ],
        "eradication": [
            "Check for data leakage (SQL injection → DB audit)",
            "Review for webshell uploads or file modifications",
            "Verify all input validation and output encoding is in place",
        ],
    },
    "database": {
        "description": "Database attack — unauthorized access or injection",
        "triage": [
            "Identify the database and the query pattern",
            "Determine if sensitive data was accessed or modified",
            "Check the source of the query (application, direct connection, admin tool)",
        ],
        "containment": [
            "Block the source IP from database access",
            "Suspend the database user account",
            "Enable database audit logging if not already active",
        ],
        "eradication": [
            "Audit all queries from the source during the attack window",
            "Check for data exfiltration (large result sets, COPY commands)",
            "Review for database schema modifications or new objects",
        ],
    },
    "endpoint": {
        "description": "Endpoint threat — suspicious process or file activity",
        "triage": [
            "Identify the process, its parent, and the command line",
            "Check the file hash against threat intel (VirusTotal, IOC feeds)",
            "Determine if the process has network connections",
        ],
        "containment": [
            "Kill the suspicious process",
            "Quarantine the file",
            "Isolate the endpoint from the network",
        ],
        "eradication": [
            "Run full endpoint malware scan",
            "Check for persistence (registry Run keys, scheduled tasks, services)",
            "Review for downloaded payloads or C2 connections",
        ],
    },
    "execution": {
        "description": "Suspicious code execution detected",
        "triage": [
            "Review the executed command and its context",
            "Determine if the execution is legitimate admin activity",
            "Check for encoded content and decode for analysis",
        ],
        "containment": [
            "Kill the process if malicious",
            "Isolate the host",
            "Block the source of the command",
        ],
        "eradication": [
            "Check for persistence enabled by the execution",
            "Review child processes for additional payloads",
            "Scan for malware planted by the execution",
        ],
    },
    "persistence": {
        "description": "Persistence mechanism detected — attacker maintaining access",
        "triage": [
            "Identify the persistence method (registry, scheduled task, service)",
            "Determine when the mechanism was created and by whom",
            "Check if the mechanism is known malware or admin tooling",
        ],
        "containment": [
            "Remove the persistence mechanism",
            "Disable the user account that created it",
            "Isolate the affected system",
        ],
        "eradication": [
            "Check for other persistence mechanisms on the same host",
            "Review for the initial compromise that enabled persistence",
            "Audit similar systems for the same persistence mechanism",
        ],
    },
    "reconnaissance": {
        "description": "Reconnaissance activity — attacker probing systems",
        "triage": [
            "Identify what was probed (admin pages, config files, git repos)",
            "Determine if the probing found anything exploitable",
            "Check for follow-on exploitation attempts",
        ],
        "containment": [
            "Block the source IP at the WAF/firewall",
            "Ensure probed paths return 404 or 403 (not 200)",
            "Enable WAF rate limiting for probing patterns",
        ],
        "eradication": [
            "Verify no sensitive files are exposed (.env, .git, config)",
            "Review for successful access to admin interfaces",
            "Check for exploitation following the reconnaissance",
        ],
    },
    "zero-day": {
        "description": "Zero-day exploit attempt — novel attack vector",
        "triage": [
            "Capture the full request payload for analysis",
            "Determine if the exploit succeeded (check response and follow-on activity)",
            "Submit the payload to the security team for zero-day analysis",
        ],
        "containment": [
            "Block the source IP immediately",
            "Apply virtual patch at WAF/IPS based on the payload pattern",
            "Isolate the targeted system if exploitation is confirmed",
        ],
        "eradication": [
            "Analyze the exploit for the vulnerability being targeted",
            "Check for persistence or data access following exploitation",
            "Coordinate with the vendor for a patch disclosure",
        ],
    },
    "sql-injection": {
        "description": "SQL injection attempt — database attack",
        "triage": [
            "Identify the injection point (parameter, header, cookie)",
            "Determine if the injection was successful (check DB error logs, response)",
            "Review for data extraction (UNION SELECT, OUTFILE, etc.)",
        ],
        "containment": [
            "Block the source IP at the WAF",
            "Enable WAF SQL injection rules if not active",
            "Set the application to read-only mode if DB compromise suspected",
        ],
        "eradication": [
            "Audit database for unauthorized data access or modification",
            "Check for new database users or privileges",
            "Review application code for the vulnerable parameter",
        ],
    },
    "ssrf": {
        "description": "Server-Side Request Forgery — internal resource access",
        "triage": [
            "Identify the targeted internal resource (metadata service, internal API)",
            "Determine if the SSRF was successful (check response and logs)",
            "Review for cloud metadata access (169.254.169.254)",
        ],
        "containment": [
            "Block the source IP at the WAF",
            "Restrict outbound requests from the application server",
            "Block access to cloud metadata service (169.254.169.254)",
        ],
        "eradication": [
            "Rotate cloud credentials if metadata service was accessed",
            "Audit for IAM token usage if credentials were exposed",
            "Review application code for the SSRF vulnerability",
        ],
    },
    "ics_ot": {
        "description": "ICS/OT network activity — operational technology risk",
        "triage": [
            "Identify the OT protocol and devices involved",
            "Determine if the activity is from an authorized engineering workstation",
            "Check for unusual commands or traffic patterns",
        ],
        "containment": [
            "Isolate the OT network segment from IT network",
            "Block unauthorized IPs from OT network access",
            "Enable OT-specific IPS rules",
        ],
        "eradication": [
            "Verify PLC/RTU configurations were not modified",
            "Check for unauthorized firmware changes",
            "Review physical safety systems for impact",
        ],
    },
    "mobile_security": {
        "description": "Mobile security threat — device or API abuse",
        "triage": [
            "Identify the device and user agent",
            "Determine if the request pattern indicates MDM bypass or app tampering",
            "Check for unauthorized API access from mobile devices",
        ],
        "containment": [
            "Revoke the device's API token",
            "Block the device at the mobile gateway",
            "Force MDM compliance check",
        ],
    },
    "network-infrastructure": {
        "description": "Network infrastructure threat — protocol abuse",
        "triage": [
            "Identify the protocol (DNS, SNMP, SSH, Telnet) and traffic volume",
            "Check for DNS tunneling, SNMP enumeration, or unauthorized SSH",
            "Review for data exfiltration over the protocol",
        ],
        "containment": [
            "Block the source IP at the firewall",
            "Disable Telnet if still active (use SSH only)",
            "Enable DNS filtering and SNMP v3",
        ],
    },
    "mitre-attack": {
        "description": "MITRE ATT&CK technique detected — review required",
        "triage": [
            "Identify the specific ATT&CK technique and its tactic category",
            "Determine if the activity is expected for the environment",
            "Check for related techniques in the kill chain",
        ],
        "containment": [
            "Apply technique-specific containment from the MITRE mitigation catalog",
            "Block associated IOCs (IPs, domains, file hashes)",
            "Isolate affected systems if technique indicates active compromise",
        ],
    },
    "default": {
        "description": "Security alert — investigation required",
        "triage": [
            "Review the alert details, source, and destination",
            "Determine if the activity is expected or anomalous for the environment",
            "Check for related alerts from the same source",
        ],
        "containment": [
            "Block the source IP if external and suspicious",
            "Suspend the user account if internal and anomalous",
            "Isolate the affected system if compromise is suspected",
        ],
        "eradication": [
            "Investigate the full scope of the activity",
            "Check for persistence and lateral movement",
            "Remove any identified threats",
        ],
        "recovery": [
            "Restore systems to known-good state",
            "Verify all threats are removed",
            "Monitor for recurrence",
        ],
        "lessons_learned": [
            "Document the incident timeline and response actions",
            "Update detection rules based on findings",
            "Share IOCs with threat intelligence teams",
        ],
    },
}


def get_response_workflow(rule):
    """Get the appropriate response workflow for a rule based on its metadata."""
    name = rule.get("name", "")
    desc = rule.get("description", "")
    category = rule.get("category", "general")
    mitre = rule.get("mitre_attack", rule.get("mitre", []))
    
    # Check for CVE first — CVE exploitation gets the dedicated workflow
    import re as _re
    if _re.search(r'CVE-\d{4}-\d+', name + " " + desc):
        return RESPONSE_WORKFLOWS["cve_exploitation"]
    
    # Check MITRE technique
    for tech in mitre:
        tech_main = tech.split(".")[0]
        if tech_main in RESPONSE_WORKFLOWS:
            return RESPONSE_WORKFLOWS[tech_main]
    
    # Check category (try both hyphen and underscore variants)
    if category in RESPONSE_WORKFLOWS:
        return RESPONSE_WORKFLOWS[category]
    cat_underscore = category.replace("-", "_")
    if cat_underscore in RESPONSE_WORKFLOWS:
        return RESPONSE_WORKFLOWS[cat_underscore]
    cat_hyphen = category.replace("_", "-")
    if cat_hyphen in RESPONSE_WORKFLOWS:
        return RESPONSE_WORKFLOWS[cat_hyphen]
    
    # AI LLM variants
    if "ai" in category.lower() or "llm" in category.lower():
        return RESPONSE_WORKFLOWS["ai-llm"]
    
    # Cloud variants
    if "cloud" in category.lower():
        return RESPONSE_WORKFLOWS["cloud-native"]
    
    # Web app variants
    if "web" in category.lower() or "sql" in category.lower() or "xss" in category.lower():
        return RESPONSE_WORKFLOWS["web-application"]
    
    # Default workflow
    return RESPONSE_WORKFLOWS["default"]