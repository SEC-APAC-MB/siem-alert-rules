#!/usr/bin/env python3
"""Regenerate production-grade detection queries for OCI (MQL) and Azure (KQL)."""
import json, glob, os, re, sys

STOPWORDS = set("""
the a an and or but of in on at to from for with by as is are was were be been has have
had over under between into through during about per via using used use user users attack
attacker detected detection detect detecting suspicious anomaly anomalous activity attempt
attempts potential potentiality indicating patterns pattern behaviour behavior builder
starts seen events event
""".split())

MITRE_FAMILY = {
    "T1078": "auth", "T1098": "audit", "T1556": "audit", "T1558": "auth",
    "T1552": "audit", "T1606": "auth", "T1539": "auth", "T1110": "auth",
    "T1555": "audit", "T1548": "audit", "T1484": "audit", "T1134": "audit",
    "T1021": "flow", "T1534": "flow", "T1557": "flow", "T1187": "flow",
    "T1041": "flow", "T1048": "flow", "T1567": "flow", "T1020": "flow",
    "T1030": "flow", "T1537": "flow", "T1572": "flow", "T1090": "flow",
    "T1071": "flow", "T1573": "flow", "T1498": "flow", "T1499": "endpoint",
    "T1190": "web", "T1203": "endpoint", "T1566": "web", "T1059": "endpoint",
    "T1053": "audit", "T1070": "audit", "T1562": "audit", "T1140": "endpoint",
    "T1005": "endpoint", "T1083": "endpoint", "T1213": "audit", "T1590": "flow",
    "T1595": "flow", "T1592": "endpoint", "T1589": "auth", "T1526": "audit",
    "T1087": "audit", "T1018": "flow", "T1046": "flow", "T1530": "object",
    "T1195": "audit", "T1550": "auth", "T1485": "audit", "T1486": "endpoint",
    "T1489": "endpoint", "T1565": "audit", "T1133": "flow", "T1204": "endpoint",
    "T1219": "flow", "T1105": "flow", "T1106": "endpoint", "T1055": "endpoint",
    "T1003": "audit", "T1136": "audit", "T1580": "auth", "T1621": "auth",
    "T1560": "endpoint", "T1569": "endpoint", "T1543": "audit", "T1547": "audit",
    "T1036": "endpoint", "T1055.011": "endpoint", "T1201": "endpoint",
    "T1040": "flow", "T1553": "defenseevasion", "T1112": "audit",
    "T1554":"endpoint", "T1525":"audit", "T1609":"flow", "T1610":"flow",
    "T1546":"audit", "T1505":"endpoint", "T1531":"endpoint", "T1490":"endpoint",
}

CATEGORY_FAMILY = {
    "database": "db", "sql-injection": "db", "sql_injection": "db",
    "lateral-movement": "flow", "lateral_movement": "flow",
    "exfiltration": "flow", "reconnaissance": "flow", "network-infrastructure": "flow",
    "initial_access": "flow", "ics_ot": "flow", "dos": "flow", "tls": "flow",
    "ransomware": "endpoint", "zero_day": "endpoint", "execution": "endpoint",
    "endpoint": "endpoint", "memory-corruption": "endpoint",
    "remote-code-execution": "endpoint", "mobile_security": "endpoint",
    "persistence": "audit", "privilege-escalation": "audit", "supply_chain": "audit",
    "cloud_native": "audit", "cloud-container": "container",
    "ai_llm_attacks": "web", "auth-bypass": "web", "xss": "web", "ssrf": "web",
    "csrf": "web", "xxe": "web", "input-validation": "web",
    "deserialization": "web", "path-traversal": "web", "redirect": "web",
    "request-smuggling": "web", "idor": "web", "info-disclosure": "web",
    "crypto": "web", "code-injection": "web", "file-upload": "web",
    "race-condition": "endpoint", "server-side-request-forgery": "web",
}

TAG_FAMILY = {
    "database": "db", "oracle-db": "db", "db": "db", "sql": "db",
    "network": "flow", "networking": "flow", "vcn": "flow",
    "iam": "audit", "identity": "audit", "governance": "audit",
    "kms": "audit", "secret": "audit", "secrets": "audit", "key": "audit",
    "container": "container", "kubernetes": "container", "k8s": "container",
    "object-storage": "object", "storage": "object",
    "ics": "flow", "ot": "flow", "scada": "flow",
}

CATEGORY_TACTIC = {
    "reconnaissance": ["Reconnaissance"], "recon": ["Reconnaissance"],
    "initial_access": ["InitialAccess"], "execution": ["Execution"],
    "persistence": ["Persistence"], "privilege-escalation": ["PrivilegeEscalation"],
    "lateral-movement": ["LateralMovement"], "lateral_movement": ["LateralMovement"],
    "exfiltration": ["Exfiltration"], "ransomware": ["Impact"],
    "dos": ["Impact"], "zero_day": ["Execution"], "endpoint": ["Execution"],
    "memory-corruption": ["DefenseEvasion"], "remote-code-execution": ["Execution"],
    "code-injection": ["Execution"], "deserialization": ["Execution"],
    "xss": ["InitialAccess"], "ssrf": ["InitialAccess"], "csrf": ["InitialAccess"],
    "xxe": ["InitialAccess"], "sql-injection": ["InitialAccess"],
    "sql_injection": ["InitialAccess"], "input-validation": ["InitialAccess"],
    "path-traversal": ["InitialAccess"], "redirect": ["InitialAccess"],
    "request-smuggling": ["InitialAccess"], "idor": ["CredentialAccess"],
    "auth-bypass": ["CredentialAccess"], "info-disclosure": ["Collection"],
    "crypto": ["Collection"], "supply_chain": ["InitialAccess"],
    "cloud_native": ["Discovery"], "ics_ot": ["ImpairProcessControl"],
    "ai_llm_attacks": ["InitialAccess"], "mobile_security": ["Execution"],
    "tls": ["CommandAndControl"], "network-infrastructure": ["Discovery"],
    "database": ["Collection"],
}

# keyword -> real OCI Audit event names
AUDIT_EVENTS = {
    "user": ["UpdateUser", "CreateUser", "DeleteUser", "AddUserToGroup", "RemoveUserFromGroup", "UpdateUserCapabilities"],
    "policy": ["CreatePolicy", "UpdatePolicy", "DeletePolicy", "ChangePolicyCompartment"],
    "group": ["CreateGroup", "UpdateGroup", "DeleteGroup", "AddUserToGroup", "RemoveUserFromGroup"],
    "bucket": ["CreateBucket", "UpdateBucket", "DeleteBucket", "CreateRetentionRule", "UpdateRetentionRule"],
    "secret": ["CreateSecret", "UpdateSecret", "UpdateSecretVersion", "ScheduleSecretDeletion", "CancelSecretDeletion"],
    "key": ["CreateKey", "UpdateKey", "CreateKeyVersion", "ScheduleKeyDeletion", "CancelKeyDeletion", "BackupKey"],
    "kms": ["CreateKey", "UpdateKey", "CreateKeyVersion", "ScheduleKeyDeletion", "CancelKeyDeletion", "BackupKey", "EncryptData", "DecryptData"],
    "instance": ["LaunchInstance", "RunInstance", "UpdateInstance", "TerminateInstance", "StopInstance", "StartInstance"],
    "volume": ["CreateVolume", "UpdateVolume", "DetachVolume", "AttachVolume", "DeleteVolume", "CreateBackup"],
    "network": ["CreateVcn", "UpdateVcn", "DeleteVcn", "CreateSubnet", "UpdateSubnet", "DeleteSubnet", "CreateSecurityList", "UpdateSecurityList", "CreateNetworkSecurityGroup", "UpdateNetworkSecurityGroup"],
    "subnet": ["CreateSubnet", "UpdateSubnet", "DeleteSubnet"],
    "vcn": ["CreateVcn", "UpdateVcn", "DeleteVcn", "CreateSubnet", "UpdateSubnet", "DeleteSubnet"],
    "security": ["CreateSecurityList", "UpdateSecurityList", "CreateNetworkSecurityGroup", "UpdateNetworkSecurityGroup"],
    "database": ["CreateDatabase", "UpdateDatabase", "DeleteDatabase", "RestoreAutonomousDatabase", "FailoverAutonomousDatabase"],
    "autonomous": ["CreateAutonomousDatabase", "UpdateAutonomousDatabase", "RestoreAutonomousDatabase", "FailoverAutonomousDatabase", "StartAutonomousDatabase", "StopAutonomousDatabase"],
    "object": ["PutObject", "DeleteObject", "AbortMultipartUpload", "ObjectRestore", "CreateObject"],
    "storage": ["PutObject", "DeleteObject", "CreateBucket", "UpdateBucket", "AbortMultipartUpload"],
    "role": ["CreateRole", "UpdateRole", "DeleteRole", "GrantRole", "RevokeRole"],
    "api": ["UpdateApiKey", "UploadApiKey", "CreateApiKey", "DeleteApiKey"],
    "token": ["CreateAuthToken", "UpdateAuthToken", "DeleteAuthToken", "CreateCustomerSecretKey", "DeleteCustomerSecretKey"],
    "oauth": ["CreateOAuthClientCredential", "UpdateOAuthClientCredential", "DeleteOAuthClientCredential"],
    "dns": ["UpdateZone", "UpdateRRSet", "DeleteRRSet", "CreateZone", "DeleteZone"],
    "domain": ["AddUsersToDomain", "RemoveUsersFromDomain", "UpdateDomain"],
    "rule": ["CreateEventRule", "UpdateEventRule", "DeleteEventRule"],
    "patching": ["CreateOsManagementSoftwareSource", "ChangeKubeconfigContent"],
    "management": ["UpdateManagementAgent", "UpdateInstanceAgentConfig"],
    "provision": ["ProvisionAutonomousDatabase", "AdvanceAutonomousDatabase"],
    "firewall": ["CreateFirewallPolicy", "UpdateFirewallPolicy"],
}

# keyword -> ports (for VcnFlowLogs)
NET_PORTS = {
    "rdp": [3389], "remote": [3389], "smb": [445, 139], "share": [445], "file": [445, 139, 2049],
    "ssh": [22], "telnet": [23], "ftp": [21, 20], "dns": [53, 5353], "ldap": [389, 636],
    "kerberos": [88], "mysql": [3306], "postgres": [5432], "postgresql": [5432], "mssql": [1433],
    "sqlserver": [1433], "sql": [1433, 1521], "redis": [6379], "mongodb": [27017], "oracle": [1521],
    "kubernetes": [6443, 10250], "k8s": [6443, 10250], "docker": [2375, 2376], "smtp": [25, 465, 587],
    "mail": [25, 465, 587], "web": [80, 443], "http": [80, 443], "https": [443], "modbus": [502],
    "s7": [102], "opc": [4840], "snmp": [161, 162], "ntp": [123], "rsync": [873],
    "vnc": [5900, 5901], "netbios": [137, 138, 139], "winrm": [5985, 5986], "rdp-3389": [3389],
}

AUDIT_RULES_KEYS = set().union(*[set(v) for v in AUDIT_EVENTS.values()])


def extract_keywords(name):
    words = re.sub(r"[^A-Za-z0-9]+", " ", name).lower().split()
    out = []
    for w in words:
        if w in STOPWORDS or len(w) < 3:
            continue
        if w not in out:
            out.append(w)
    return out[:2]


def safe_tok(s):
    return re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_").lower()


def family_for(rule):
    mitre = rule.get("mitre_attack") or rule.get("mitre") or []
    category = rule.get("category") or "general"
    tags = [safe_tok(t) for t in (rule.get("tags") or [])]
    name = rule.get("name", "")
    if "CVE-" in name or "cve" in tags:
        return "cve"
    for tech in mitre:
        t = tech.split(".")[0]
        if t in MITRE_FAMILY:
            return MITRE_FAMILY[t]
    cat_n = cat_norm(category)
    if cat_n in CATEGORY_FAMILY:
        return CATEGORY_FAMILY[cat_n]
    for t in tags:
        if t in TAG_FAMILY:
            return TAG_FAMILY[t]
    if cat_n in ("general", "other"):
        return "general"
    return "endpoint"


def cat_norm(cat):
    c = safe_tok(cat).replace("_", "-")
    return c


def oci_metric_token(rule):
    cat = safe_tok(rule.get("category") or "general")
    rid = rule["rule_id"].replace("OCI-", "", 1)
    return f"siem_{cat}_{safe_tok(rid)}"


def _events_for(kw):
    if not kw:
        return []
    if kw in AUDIT_EVENTS:
        return AUDIT_EVENTS[kw]
    for k, v in AUDIT_EVENTS.items():
        if k in kw:
            return v
    return []


def _ports_for(kw):
    if not kw:
        return []
    if kw in NET_PORTS:
        return NET_PORTS[kw]
    for k, v in NET_PORTS.items():
        if k in kw:
            return v
    return []


def oci_query(rule, family, kw):
    cat = safe_tok(rule.get("category") or "general").lower()
    tok = oci_metric_token(rule)
    rid = rule["rule_id"]
    sev = rule.get("severity", "MEDIUM")
    thr = rule.get("condition", {}).get("threshold", 3)
    kw0 = kw[0] if kw else (cat or "anomaly")
    kw1 = kw[1] if len(kw) > 1 else kw0

    def base(src, dim):
        return (f'SELECT "{tok}", "{dim}" FROM "oci_monitoring_metricexplorer_metrics" '
                f'WHERE "compartmentId" = \'$COMPARTMENT_ID\' AND "namespace" = \'{src}\'')

    if family == "audit":
        ev = _events_for(kw0) or _events_for(kw1)
        if ev:
            inl = ", ".join(f"'{e}'" for e in ev)
            return (base("AuditEvents", "data__json.rEventName")
                    + f' AND "data__json.rEventName" IN ({inl}) AND "value" > 0')
        return (base("AuditEvents", "data__json.rEventName")
                + f" AND \"data__json.rEventName\" LIKE '%{kw0}%' AND \"value\" > 0")
    if family == "flow":
        ports = _ports_for(kw0) or _ports_for(kw1)
        if ports:
            inl = ", ".join(str(p) for p in ports)
            return (base("VcnFlowLogs", "action")
                    + f" AND \"action\" = 'REJECT' AND \"dstport\" IN ({inl}) AND \"value\" > 0")
        return (base("VcnFlowLogs", "action")
                + " AND \"action\" = 'REJECT' AND \"srcaddr\" NOT LIKE '10.%' "
                  "AND \"dstaddr\" NOT LIKE '10.%' AND \"value\" > 0")
    if family == "db":
        dbmetric = {"cpu": "CPUUtilization", "memory": "ActiveSessions",
                    "session": "ActiveSessions", "connection": "ConnectionCount",
                    "fail": "FailedConnections", "storage": "StorageUtilization",
                    "backup": "StorageUtilization"}.get(kw0, "FailedConnections")
        return (base("oci_database", "metricName")
                + f' AND "metricName" = \'{dbmetric}\' AND "value" > {max(1, int(thr) * 10)}')
    if family == "object":
        return (base("oci_objectstorage", "metricName")
                + " AND \"metricName\" = 'StorageSizeBytes' AND \"value\" > 0")
    if family == "container":
        return (base("OciLoggingService", "data__json.message")
                + f" AND \"data__json.type\" = 'container' AND (\"data__json.message\" LIKE '%{kw0}%' "
                  f"OR \"data__json.message\" LIKE '%{kw1}%') AND \"value\" > 0")
    if family == "compute":
        return (base("oci_computeagent", "metricName")
                + " AND \"metricName\" IN ('CpuUtilization', 'MemoryUtilization') AND \"value\" > 90")
    if family == "lb":
        return (base("oci_lbaas", "metricName")
                + " AND \"metricName\" = 'HealthyHostCount' AND \"value\" < 1")
    if family == "web":
        return (base("OciLoggingService", "data__json.message")
                + f" AND (\"data__json.message\" LIKE '%{kw0}%' OR \"data__json.message\" LIKE '%{kw1}%') "
                  "AND \"value\" > 0")
    if family == "endpoint":
        return (base("OciLoggingService", "data__json.message")
                + f" AND (\"data__json.message\" LIKE '%{kw0}%' OR \"data__json.message\" LIKE '%{kw1}%') "
                  "AND \"value\" > 0")
    if family == "cve":
        return (base("OciLoggingService", "data__json.message")
                + f" AND (\"data__json.message\" LIKE '%{kw0}%' OR \"data__json.message\" LIKE '%{kw1}%') "
                  "AND (\"data__json.message\" LIKE '%CVE-%' OR \"data__json.message\" LIKE '%exploit%') "
                  "AND \"value\" > 0")
    # general
    return (base("OciLoggingService", "data__json.message")
            + f" AND (\"data__json.message\" LIKE '%{kw0}%' OR \"data__json.message\" LIKE '%{kw1}%') "
              "AND \"value\" > 0")


def oci_event_type(family):
    if family == "audit":
        return ["com.oracle.cloud.audit", "com.oracle.cloud.monitoring"]
    return ["com.oracle.cloud.monitoring"]


def kql_tactics(rule, family):
    mitre = rule.get("mitre_attack") or rule.get("mitre") or []
    seen = []
    for tech in mitre:
        t = map_tactic(tech)
        if t and t not in seen:
            seen.append(t)
    if seen:
        return seen
    cat_n = cat_norm(rule.get("category") or "general")
    if cat_n in CATEGORY_TACTIC:
        return CATEGORY_TACTIC[cat_n]
    if family == "audit":
        return ["Persistence"]
    if family == "cve":
        return ["InitialAccess"]
    if family == "flow":
        return ["CommandAndControl"]
    if family == "db":
        return ["Collection"]
    if family == "object":
        return ["Exfiltration"]
    return ["Discovery"]


MITRE_TACTIC_EXT = {
    "T1078": "DefenseEvasion", "T1098": "Persistence", "T1556": "CredentialAccess",
    "T1558": "CredentialAccess", "T1552": "CredentialAccess", "T1606": "CredentialAccess",
    "T1539": "CredentialAccess", "T1110": "CredentialAccess", "T1555": "CredentialAccess",
    "T1548": "PrivilegeEscalation", "T1484": "DefenseEvasion", "T1134": "DefenseEvasion",
    "T1021": "LateralMovement", "T1534": "LateralMovement", "T1557": "CredentialAccess",
    "T1187": "CredentialAccess", "T1041": "Exfiltration", "T1048": "Exfiltration",
    "T1567": "Exfiltration", "T1020": "Exfiltration", "T1030": "Exfiltration",
    "T1537": "Exfiltration", "T1572": "CommandAndControl", "T1090": "CommandAndControl",
    "T1071": "CommandAndControl", "T1573": "CommandAndControl", "T1498": "Impact",
    "T1499": "Impact", "T1190": "InitialAccess", "T1203": "Execution",
    "T1566": "InitialAccess", "T1059": "Execution", "T1053": "Execution",
    "T1070": "DefenseEvasion", "T1562": "DefenseEvasion", "T1140": "DefenseEvasion",
    "T1005": "Collection", "T1083": "Discovery", "T1213": "Collection",
    "T1590": "Reconnaissance", "T1595": "Reconnaissance", "T1592": "Reconnaissance",
    "T1589": "Reconnaissance", "T1526": "Discovery", "T1087": "Discovery",
    "T1018": "Discovery", "T1046": "Discovery", "T1530": "Collection",
    "T1195": "InitialAccess", "T1550": "DefenseEvasion", "T1485": "Impact",
    "T1486": "Impact", "T1489": "Impact", "T1565": "Impact", "T1133": "InitialAccess",
    "T1204": "Execution", "T1219": "CommandAndControl", "T1105": "CommandAndControl",
    "T1106": "Execution", "T1055": "DefenseEvasion", "T1003": "CredentialAccess",
    "T1136": "Persistence", "T1580": "CredentialAccess", "T1621": "CredentialAccess",
    "T1560": "Collection", "T1569": "Execution", "T1543": "Persistence",
    "T1547": "Persistence", "T1036": "DefenseEvasion", "T1201": "Discovery",
    "T1040": "CredentialAccess", "T1112": "DefenseEvasion", "T1554": "Persistence",
    "T1525": "Persistence", "T1609": "ImpairProcessControl", "T1610": "InhibitResponseFunction",
    "T1546": "PrivilegeEscalation", "T1505": "Persistence", "T1531": "Impact",
    "T1490": "Impact",
}


def map_tactic(technique):
    t = technique.split(".")[0]
    return MITRE_TACTIC_EXT.get(t, "")


KQL_KIND = {
    "auth": "SigninLogs", "audit": "AuditLogs", "db": "AzureDiagnostics",
    "ics": "CommonSecurityLog", "object": "StorageBlobLogs", "container": "KubeEvents",
}

def kql_query(rule, family, kw, threshold):
    rid = rule["rule_id"]
    cat = safe_tok(rule.get("category") or "general").lower()
    kw0 = kw[0] if kw else (cat or "anomaly")
    kw1 = kw[1] if len(kw) > 1 else kw0
    t = f" // {rid}"

    def th(n):
        return f" | where count_ > {n}"

    if family == "cve":
        cve = re.search(r"CVE-\d{4}-\d+", rule.get("name", "") + " " + rule.get("description", ""))
        cveid = cve.group(0) if cve else re.sub(r"[^A-Za-z0-9]+", "*", kw0)
        return ("union CommonSecurityLog, SecurityEvent"
                + f' | where Message has "{cveid}" or RuleName has "{cveid}" or ProcessName has "{cveid}"'
                + " | summarize count() by bin(TimeGenerated, 5m), Computer, EventID"
                + th(threshold) + t)
    if family == "auth":
        return ("SigninLogs"
                + f' | where UserPrincipalName contains "{kw0}" or IPAddress !startswith "10."'
                + " | where ResultType == \"50126\" or ResultType == \"50057\""
                + " | summarize count() by bin(TimeGenerated, 5m), UserPrincipalName, IPAddress"
                + th(threshold) + t)
    if family == "audit":
        ev = _events_for(kw0) or _events_for(kw1)
        if ev:
            inl = ", ".join(f'"{e}"' for e in ev)
            return ("AuditLogs"
                    + f" | where OperationName in ({inl})"
                    + " | summarize count() by bin(TimeGenerated, 5m), InitiatedBy, TargetResources"
                    + th(threshold) + t)
        return ("AuditLogs"
                + f" | where OperationName contains \"{kw0}\""
                + " | summarize count() by bin(TimeGenerated, 5m), InitiatedBy"
                + th(threshold) + t)
    if family == "flow":
        is_exfil = "exfil" in cat_norm(rule.get("category") or "")
        ports = _ports_for(kw0) or _ports_for(kw1)
        parts = ["CommonSecurityLog"]
        if ports:
            inl = ", ".join(str(p) for p in ports)
            parts.append(f"| where DestinationPort in ({inl})")
            parts.append("| where DeviceAction == \"Denied\" or DeviceAction == \"Blocked\"")
        elif is_exfil:
            parts.append("| where SentBytes > 5242880")
            parts.append("| where DestinationIP !startswith \"10.\" and SourceIP !startswith \"10.\"")
        else:
            parts.append("| where DestinationIP !startswith \"10.\" and SourceIP !startswith \"10.\"")
        parts.append("| summarize count() by bin(TimeGenerated, 5m), SourceIP, DestinationIP")
        return "".join(parts) + th(threshold) + t
    if family == "web":
        return (f"union CommonSecurityLog, AzureDiagnostics | where Message contains \"{kw0}\" or Msg contains \"{kw1}\" or message_s contains \"{kw0}\""
                + " | summarize count() by bin(TimeGenerated, 5m), SourceIP"
                + th(threshold) + t)
    if family == "endpoint":
        return ("SecurityEvent"
                + f" | where EventID == 4688 | where NewProcessName contains \"{kw0}\" or CommandLine contains \"{kw1}\""
                + " | summarize count() by bin(TimeGenerated, 5m), Computer, Account, NewProcessName"
                + th(threshold) + t)
    if family == "db":
        return ("AzureDiagnostics"
                + f" | where Category == \"SQLSecurityAuditEvents\" | where statement_s contains \"{kw0}\" or action_name_s contains \"{kw1}\""
                + " | summarize count() by bin(TimeGenerated, 5m), database_name_s, session_server_principal_name_s"
                + th(threshold) + t)
    if family == "object":
        return ("StorageBlobLogs"
                + f" | where OperationName contains \"{kw0}\""
                + " | summarize count() by bin(TimeGenerated, 5m), AccountName, ObjectKey"
                + th(threshold) + t)
    if family == "container":
        return ("KubeEvents | where Reason == \"Killing\" or Reason == \"Failed\""
                + f" | where Message contains \"{kw0}\""
                + " | summarize count() by bin(TimeGenerated, 5m), Namespace, PodName"
                + th(threshold) + t)
    # general
    return ("union CommonSecurityLog, SecurityEvent"
            + f' | where Message contains "{kw0}" or Message contains "{kw1}"'
            + " | summarize count() by bin(TimeGenerated, 5m), Computer"
            + th(threshold) + t)


def azure_threshold(rule):
    cur = rule.get("triggerThreshold")
    if isinstance(cur, int) and cur > 0:
        return cur
    sev = rule.get("severity", 2)
    if sev <= 1:
        return 1
    if sev == 2:
        return 5
    return 10


def mql_syntax_ok(q):
    if not q.startswith("SELECT"):
        return False, "must start with SELECT"
    if "FROM" not in q.upper():
        return False, "missing FROM"
    if "WHERE" not in q.upper():
        return False, "missing WHERE"
    if "oci_monitoring_metricexplorer_metrics" not in q:
        return False, "missing metric explorer table"
    if "$COMPARTMENT_ID" not in q:
        return False, "missing $COMPARTMENT_ID"
    for a, b in [("(", ")"), ("'", "'"), ('"', '"')]:
        if q.count(a) != q.count(b):
            return False, f"unbalanced {a}{b}"
    return True, ""


def kql_syntax_ok(q):
    if "|" not in q:
        return False, "no pipe operators"
    if "summarize count() by" not in q:
        return False, "missing summarize count"
    for a, b in [("(", ")"), ('"', '"'), ("[", "]")]:
        if q.count(a) != q.count(b):
            return False, f"unbalanced {a}{b}"
    return True, ""


def process_oracle(path, report):
    with open(path) as f:
        data = json.load(f)
    changed = 0
    for r in data["rules"]:
        kw = extract_keywords(r["name"])
        fam = family_for(r)
        q = oci_query(r, fam, kw)
        ok, why = mql_syntax_ok(q)
        if not ok:
            report["errors"].append(f'{r["rule_id"]}: MQL {why}')
            continue
        prev = r.get("query")
        met = oci_metric_token(r)
        r["query"] = q
        cond = r.setdefault("condition", {})
        cond["eventType"] = oci_event_type(fam)
        cond["metric"] = met
        changed += 1
        if prev: 
            report["mql"].append((prev, q))
    data["total_rules"] = len(data["rules"])
    if changed:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        report["files"].append((path, changed))


_AZ_DUP = set()


def process_azure(path, report):
    with open(path) as f:
        data = json.load(f)
    changed = 0
    for r in data["rules"]:
        q = (r.get("query") or "").strip()
        regenerate = (not q) or q in _AZ_DUP
        if regenerate:
            kw = extract_keywords(r["name"])
            fam = family_for(r)
            thr = azure_threshold(r)
            q = kql_query(r, fam, kw, thr)
            ok, why = kql_syntax_ok(q)
            if not ok:
                report["errors"].append(f'{r["rule_id"]}: KQL {why}')
                continue
            r["query"] = q
            r["triggerThreshold"] = thr
            r["triggerOperator"] = "GreaterThan"
            r["queryFrequency"] = r.get("queryFrequency", "5m")
            r["queryPeriod"] = r.get("queryPeriod", "10m")
            changed += 1
        if not r.get("tactics"):
            r["tactics"] = kql_tactics(r, family_for(r))
            changed += 1
    if changed:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        report["files"].append((path, changed))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    report = {"files": [], "errors": [], "mql": []}
    import collections as _cc
    # precompute azure duplicate query map so process_azure can regenerate shared templates
    audit = None
    if mode in ("azure", "all"):
        qcount = _cc.Counter()
        for p in glob.glob("rules/azure/*.json"):
            with open(p) as f:
                data = json.load(f)
            for r in data["rules"]:
                q = (r.get("query") or "").strip()
                qcount[q] += 1
        global _AZ_DUP
        _AZ_DUP = set(q for q, c in qcount.items() if c > 1)
    if mode in ("oracle", "all"):
        for p in sorted(glob.glob("rules/oracle/*.json")):
            process_oracle(p, report)
    if mode in ("azure", "all"):
        for p in sorted(glob.glob("rules/azure/*.json")):
            process_azure(p, report)

    # uniqueness check across platform
    import collections
    report["uniqueness"] = {}
    for plat in ("oracle", "azure"):
        qs = collections.Counter()
        for p in glob.glob(f"rules/{plat}/*.json"):
            with open(p) as f:
                data = json.load(f)
            for r in data["rules"]:
                qs[r["query"]] += 1
        dup = {q: c for q, c in qs.items() if c > 1}
        report["uniqueness"][plat] = {
            "total_rules": sum(qs.values()),
            "unique_queries": len(qs),
            "duplicate_query_strings": len(dup),
            "rules_sharing_duplicate_queries": sum(dup.values()),
        }
        if dup:
            most = max(dup.items(), key=lambda kv: kv[1])
            report["uniqueness"][plat]["worst"] = {"count": most[1], "query": most[0]}
    report["mql"].clear()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()