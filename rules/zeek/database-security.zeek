# =============================================================================
# Zeek Signatures — Database Security
# Total rules: 42
# MITRE ATT&CK: T1190, T1552, T1548, T1485, T1567, T1078, T1213, T1040
# Compliance: PCI-DSS 6.5, GDPR 32, HIPAA 164.312, NIST SI-4, AC-3, IA-5
# =============================================================================

@load base/frameworks/signatures/main
@load base/protocols/http/software

# =============================================================================
# SQL Injection
# =============================================================================

signature ZK-DBSEC-001 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 27017 6379 }
	payload /.*(\bUNION\b.*\bSELECT\b|\bOR\b\s+1\s*=\s*1|'\s*OR\s*'|;\s*DROP\s|\bSLEEP\s*\(|\bBENCHMARK\s*\().*/ regex
	event "DB-SEC-001: Classic SQL injection pattern detected on database port"
}

signature ZK-DBSEC-002 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/api\/v[0-9]+\/.*(\?|%3F).*(UNION%20(ALL%20)?SELECT|OR%201%3D1|'%20OR%20'|%3B%20DROP%20|SLEEP%28|BENCHMARK%28).*/ regex
	event "DB-SEC-002: SQL injection via API parameter"
}

signature ZK-DBSEC-003 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /(200 OK|500 Internal Server Error)/ regex
	payload /.*(ORA-\d{5}|Microsoft OLE DB|PostgreSQL query failed|mysql_fetch|SQLSTATE|Unclosed quotation mark|Warning: mysql_|SQL error|ODBC SQL Server).*/ regex
	event "DB-SEC-003: SQL injection - database error message disclosure"
}

signature ZK-DBSEC-004 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bSLEEP\s*\(|\bWAITFOR\s+DELAY\b|\bBENCHMARK\s*\(|\bpg_sleep\s*\(|\bdbms_pipe\.receive_message\b).*/ regex
	event "DB-SEC-004: Time-based blind SQL injection detected"
}

# =============================================================================
# Unauthorized Database Access
# =============================================================================

signature ZK-DBSEC-005 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 27017 }
	src-ip = !192.168.1.0/24
	src-ip = !10.0.0.0/8
	src-ip = !172.16.0.0/12
	event "DB-SEC-005: Database connection from unauthorized IP address"
}

signature ZK-DBSEC-006 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(root|admin|sa|postgres|dba|sys|system|master|dbo|mysql|oracle|test|guest).*/ regex
	event "DB-SEC-006: Database login with default/administrative username"
}

# =============================================================================
# Database Privilege Escalation
# =============================================================================

signature ZK-DBSEC-007 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bGRANT\s+(ALL|DBA|SUPERUSER|ADMIN)|ALTER\s+USER.*WITH\s+(SUPERUSER|CREATEDB|CREATEROLE)|EXECUTE\s+AS\s+(OWNER|CALLER)|SET\s+ROLE\s+(dbo|sysadmin|root)).*/ regex
	event "DB-SEC-007: Database privilege escalation attempt"
}

signature ZK-DBSEC-008 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(xp_cmdshell|sp_OACreate|sp_OAMethod|sp_executesql|DBMS_SCHEDULER|UTL_FILE|UTL_HTTP|UTL_TCP|DBMS_LOB).*/ regex
	event "DB-SEC-008: Dangerous stored procedure execution attempt"
}

# =============================================================================
# Database Data Exfiltration
# =============================================================================

signature ZK-DBSEC-009 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bINTO\s+OUTFILE\b|\bINTO\s+DUMPFILE\b|\bCOPY\b.*\bTO\b|\bmysqldump\b|\bpg_dump\b|\bexp\b.*\btables?\b|\bSQLCMD\b.*\b-b\b|\bbcp\b.*\bout\b).*/ regex
	event "DB-SEC-009: Database bulk data export detected"
}

signature ZK-DBSEC-010 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*\b(SELECT|FROM)\b.*(users?|accounts?|transactions?|payments?|credit_cards?|ssn|patients?|employees?|financial).*(\bWHERE\b|\bLIMIT\b|\bORDER\b).*/ regex
	event "DB-SEC-010: Database query accessing sensitive table"
}

# =============================================================================
# Schema Modification
# =============================================================================

signature ZK-DBSEC-011 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bCREATE\s+(TABLE|DATABASE|SCHEMA|USER|ROLE|FUNCTION|PROCEDURE|TRIGGER|VIEW)|\bALTER\s+(TABLE|DATABASE|SCHEMA|USER|ROLE)|\bDROP\s+(TABLE|DATABASE|SCHEMA|USER|ROLE|FUNCTION|PROCEDURE|TRIGGER|VIEW)|\bTRUNCATE\s).*/ regex
	event "DB-SEC-011: Database DDL operation detected - schema modification"
}

signature ZK-DBSEC-012 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bUPDATE\b|\bDELETE\b)\s+(users?|accounts?|transactions?|payments?|customers?|patients?|employees?|financial).*(\bSET\b|\bWHERE\b).*/ regex
	event "DB-SEC-012: Database UPDATE/DELETE on sensitive table"
}

# =============================================================================
# Database Brute Force
# =============================================================================

signature ZK-DBSEC-013 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 3389 22 }
	payload /.*(Access denied|Login failed|Authentication failed|Invalid credentials|Wrong password|Login incorrect).*/ regex
	event "DB-SEC-013: Database authentication failure - potential brute force"
}

signature ZK-DBSEC-014 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(admin|root|sa|postgres|dba|sys|system|master|dbo|mysql|oracle|test|guest).*(password|passwd|pwd|pass).*/ regex
	event "DB-SEC-014: Database login attempt with default credentials"
}

# =============================================================================
# Database Error Disclosure
# =============================================================================

signature ZK-DBSEC-015 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /500 Internal Server Error/ regex
	payload /.*(table.*doesn't exist|column.*not found|relation.*does not exist|invalid column name|incorrect syntax near|unclosed quotation mark|string or binary data would be truncated|cannot insert duplicate key|violation of.*constraint).*/ regex
	event "DB-SEC-015: Database error message disclosed to client - information leakage"
}

# =============================================================================
# Unencrypted Connection
# =============================================================================

signature ZK-DBSEC-016 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 27017 }
	payload /.*SSL.*not.*enabled|.*TLS.*not.*configured|.*encryption.*disabled|.*plaintext.*connection.*/ regex
	event "DB-SEC-016: Database connection without encryption"
}

# =============================================================================
# NoSQL Injection
# =============================================================================

signature ZK-DBSEC-017 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 27017 }
	http-request /(POST|PUT|PATCH) \/(api|query|find|search)/ regex
	payload /.*(\$where|\$gt|\$gte|\$lt|\$lte|\$ne|\$in|\$nin|\$regex|\$expr|\$jsonSchema).*/ regex
	event "DB-SEC-017: NoSQL injection operator detected"
}

signature ZK-DBSEC-018 {
	ip-proto tcp
	dst-port = { 27017 27018 27019 }
	payload /.*(\$where|\$gt|\$gte|\$lt|\$lte|\$ne|\$regex|\$expr).*(this\.\w+\s*==|this\.\w+\s*===|this\.\w+\s*match|return\s+true|return\s+1).*/ regex
	event "DB-SEC-018: MongoDB \$where injection with JavaScript execution"
}

# =============================================================================
# Database Credential Dumping
# =============================================================================

signature ZK-DBSEC-019 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bSELECT\b.*\bFROM\b\s+(mysql\.user|pg_shadow|sys\.sql_logins|sys\.database_principals|dba_users|sys\.login_token)|\bSELECT\b.*password_hash\b|\bSELECT\b.*\bFROM\b\s+information_schema\.\s*).*/ regex
	event "DB-SEC-019: Database credential dumping attempt"
}

# =============================================================================
# Database Audit Log Tampering
# =============================================================================

signature ZK-DBSEC-020 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bALTER\s+SYSTEM\s+SET\s+audit|SET\s+audit_trail\s*=\s*FALSE|sp_configure\s+'audit'|ALTER\s+DATABASE\s+.*\bSET\s+.*audit_off|\bTRUNCATE\s+(audit|log|history)).*/ regex
	event "DB-SEC-020: Database audit logging disable/tampering attempt"
}

# =============================================================================
# Database OS Command Execution
# =============================================================================

signature ZK-DBSEC-021 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(xp_cmdshell|sys_exec|sys_eval|LOAD_FILE|INTO OUTFILE|COPY\s+.*FROM\s+PROGRAM|\\!\s*\(|\\\\\s*!|dbms_scheduler|CREATE\s+EXTERNAL\s+TABLE).*/ regex
	event "DB-SEC-021: Database OS command execution attempt"
}

# =============================================================================
# Large Result Set / Data Exfiltration
# =============================================================================

signature ZK-DBSEC-022 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*\bSELECT\b.*\bFROM\b.*(users?|accounts?|transactions?|payments?|credit_cards?|ssn|patients?|employees?|financial).*/ regex
	event "DB-SEC-022: SELECT on sensitive table - monitor for large result set"
}

# =============================================================================
# Database Ransomware
# =============================================================================

signature ZK-DBSEC-023 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bDROP\s+TABLE\b|\bDROP\s+DATABASE\b|\bALTER\s+TABLE\s+\w+\s+ENCRYPT\b|\bCREATE\s+TABLE\s+\w+_locked\b|\bCREATE\s+TABLE\s+\w+_encrypted\b|\bUPDATE\s+\w+\s+SET\s+\w+\s*=.*YOUR_DATA_HAS_BEEN_LOCKED).*/ regex
	event "DB-SEC-023: Database ransomware activity detected"
}

# =============================================================================
# Excessive Privileges
# =============================================================================

signature ZK-DBSEC-024 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bGRANT\s+(ALL|DBA|SUPERUSER|ADMIN|GRANT\s+OPTION)|\bALL\s+PRIVILEGES\b).*/ regex
	event "DB-SEC-024: Excessive database privilege grant detected"
}

# =============================================================================
# Database Schema Enumeration
# =============================================================================

signature ZK-DBSEC-025 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bSELECT\b.*\bFROM\b\s+information_schema\.|SHOW\s+(TABLES|DATABASES|COLUMNS|INDEX)|\bDESCRIBE\b\s+\w+|\bEXPLAIN\b\s+|SELECT\s+table_name\s+FROM|SELECT\s+column_name\s+FROM).*/ regex
	event "DB-SEC-025: Database schema enumeration attempt"
}

# =============================================================================
# Stored XSS via Data Insertion
# =============================================================================

signature ZK-DBSEC-026 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*\b(INSERT|UPDATE)\b.*(&lt;script|javascript:|onerror\s*=|onload\s*=|&lt;img\s|&lt;svg\s|&lt;iframe\s|document\.cookie|document\.location).*/ regex
	event "DB-SEC-026: XSS payload in database INSERT/UPDATE statement"
}

# =============================================================================
# Database Backup Security
# =============================================================================

signature ZK-DBSEC-027 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(backup|db_backup|database|dump|export|download)\.(sql|bak|dump|csv|gz|tar|zip)/ regex
	event "DB-SEC-027: Database backup file accessible via HTTP"
}

# =============================================================================
# Anomalous Access Pattern
# =============================================================================

signature ZK-DBSEC-028 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*\bSELECT\b.*\bFROM\b.*(users?|accounts?|transactions?|payments?|credit_cards?|ssn|patients?|employees?|financial).*(\bLIMIT\s+[0-9]{5,}|\bWHERE\s+1\s*=\s*1|\bWHERE\s+true\b).*/ regex
	event "DB-SEC-028: Database query with excessive LIMIT or unrestricted WHERE - potential exfiltration"
}

# =============================================================================
# Temp Table Abuse
# =============================================================================

signature ZK-DBSEC-029 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bCREATE\s+(TEMP|TEMPORARY)\s+TABLE\b|\bINSERT\s+INTO\s+#\w+|\bSELECT\s+.*\s+INTO\s+(TEMP|TMP|#)|\bCREATE\s+TABLE\s+tmp_\w+).*/ regex
	event "DB-SEC-029: Database temporary table creation - potential data staging"
}

# =============================================================================
# Connection from Unusual Geography
# =============================================================================

signature ZK-DBSEC-030 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 27017 }
	src-ip = !$HOME_NET
	event "DB-SEC-030: Database connection from external IP address"
}

# =============================================================================
# Database Weak Password
# =============================================================================

signature ZK-DBSEC-031 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(password|passwd|pwd|pass).*(admin|root|test|guest|default|123456|password|qwerty|letmein|welcome|monkey|dragon|master|changeme).*/ regex
	event "DB-SEC-031: Database login with weak password"
}

# =============================================================================
# Shared Account Detection
# =============================================================================

signature ZK-DBSEC-032 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(app_user|service_account|read_only|reporting|application|shared|generic).*(login|connect|authenticate|session).*/ regex
	event "DB-SEC-032: Database connection with shared/generic account"
}

# =============================================================================
# Database Sensitive Table Access Non-Business Hours
# =============================================================================

signature ZK-DBSEC-033 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*\bSELECT\b.*\bFROM\b\s+(users?|accounts?|transactions?|payments?|credit_cards?|ssn|patients?|employees?|financial).*/ regex
	event "DB-SEC-033: Database access to sensitive table - verify business hours"
}

# =============================================================================
# Database Lateral Movement
# =============================================================================

signature ZK-DBSEC-034 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bOPENQUERY\b|\bOPENROWSET\b|\bOPENDATASOURCE\b|\bOPENJSON\b|EXEC\s+AT\s+\w+|SELECT\s+.*\s+FROM\s+\w+\.\w+\.\w+).*/ regex
	event "DB-SEC-034: Database lateral movement via linked server/openquery"
}

# =============================================================================
# Database Error Disclosure (HTTP)
# =============================================================================

signature ZK-DBSEC-035 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-response /200 OK/ regex
	http-header /Content-Type: application\/json/ regex
	payload /.*(ORA-\d{5}|SQLSTATE\[|MySQL Error|PostgreSQL query failed|Unclosed quotation mark|Microsoft OLE DB|connection string|jdbc:|mongodb:).*/ regex
	event "DB-SEC-035: Database error disclosed in API JSON response"
}

# =============================================================================
# Database Unencrypted Backup
# =============================================================================

signature ZK-DBSEC-036 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(backup|db_backup|database|dump|export|download)\.(sql|bak|dump|csv)/ regex
	http-header /!(Content-Encoding: (gzip|br|deflate))/ regex
	event "DB-SEC-036: Database backup download without encryption"
}

# =============================================================================
# Database Password in Configuration
# =============================================================================

signature ZK-DBSEC-037 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /\/(config|configuration|settings|appsettings|database|db)\.(yml|yaml|json|xml|ini|conf|env|properties)/ regex
	http-response /200 OK/ regex
	payload /.*(password\s*=\s*|ConnectionString.*Password=|jdbc:.*password=|DB_PASSWORD=).*/ regex
	event "DB-SEC-037: Database configuration file with plaintext password accessible"
}

# =============================================================================
# Database Stored Procedure Abuse (HTTP)
# =============================================================================

signature ZK-DBSEC-038 {
	ip-proto tcp
	dst-port = { 80 443 8080 8443 }
	http-request /(POST|PUT|PATCH) \/api\/v[0-9]+\/(query|execute|run|call|procedure)/ regex
	payload /.*(xp_cmdshell|sp_OACreate|sp_OAMethod|sp_executesql|DBMS_SCHEDULER|UTL_FILE|UTL_HTTP|UTL_TCP|DBMS_LOB).*/ regex
	event "DB-SEC-038: Stored procedure abuse via API"
}

# =============================================================================
# Database Connection Pool Exhaustion
# =============================================================================

signature ZK-DBSEC-039 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(connection.*timeout|pool.*exhausted|max.*connections.*reached|too.*many.*connections|connection.*refused).*/ regex
	event "DB-SEC-039: Database connection pool exhaustion detected"
}

# =============================================================================
# Database Privileged Account Outside Maintenance
# =============================================================================

signature ZK-DBSEC-040 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(root|admin|sa|postgres|dba|sys|system|master|dbo)\s*(login|connect|authenticate|session).*/ regex
	event "DB-SEC-040: Database privileged account connection - verify maintenance window"
}

# =============================================================================
# Database Full Table Scan
# =============================================================================

signature ZK-DBSEC-041 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*\bSELECT\s+\*\s+FROM\b.*/ regex
	event "DB-SEC-041: Database SELECT * detected - potential full table scan"
}

# =============================================================================
# Database Error-Based Extraction
# =============================================================================

signature ZK-DBSEC-042 {
	ip-proto tcp
	dst-port = { 3306 5432 1433 1521 }
	payload /.*(\bCASE\b.*\bWHEN\b.*\bTHEN\b|\bIF\b\s*\(.*\bTHEN\b|\bCOALESCE\b.*\bSELECT\b|\bCAST\b.*\bAS\b.*\bCONVERT\b).*/ regex
	event "DB-SEC-042: Conditional SQL expression - error-based data extraction attempt"
}