#!/usr/bin/env python3
"""
Master SIEM Alert Rules Generator — Complete Repository Builder
Generates ALL rule files for ALL 11 platforms, all mappings, docs, and scripts.
"""
import json, os, sys, hashlib
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(BASE, "rules")
MAPPINGS = os.path.join(BASE, "mappings")
DOCS = os.path.join(BASE, "docs")
SCRIPTS = os.path.join(BASE, "scripts")

PLATFORMS = ["elastic","splunk","fortisiem","qradar","sentinel","wazuh","zeek","suricata","oracle","azure","aws"]

for p in PLATFORMS:
    os.makedirs(os.path.join(RULES, p), exist_ok=True)
os.makedirs(MAPPINGS, exist_ok=True)
os.makedirs(DOCS, exist_ok=True)
os.makedirs(SCRIPTS, exist_ok=True)

SEV_NUM = {"critical": 9, "high": 7, "medium": 5, "low": 3, "informational": 1}
SEV_FORT = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Info"}
SEV_SENT = {"critical": "High", "high": "Medium", "medium": "Low", "low": "Informational", "informational": "Informational"}
SEV_OCI = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "INFO"}
SEV_AZURE = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

# ============================================================
# COMPREHENSIVE RULE DEFINITIONS
# ============================================================
# Each rule: id, name, desc, sev, tags, mitre, compliance, query_hint (for search patterns)

ALL_RULES = {}

# --- WSTG 01-03: Info Gathering, Configuration, Identity Mgmt ---
ALL_RULES["wstg-01-03"] = [
    {"id":"WSTG01-001","name":"Search Engine Discovery of Sensitive Content","desc":"Detects search engine crawlers accessing sensitive paths like /admin, /.env, /.git, /wp-admin, /backup, /config","sev":"low","tags":["wstg","information-gathering","reconnaissance","search-engine"],"mitre":["T1595","T1592"],"compliance":["PCI-DSS-11.3","NIST-RA-5","GDPR-32A-001"],"qh":"Googlebot|bingbot|/admin|/.env|/.git|/wp-admin"},
    {"id":"WSTG01-002","name":"Web Server Fingerprinting via Headers","desc":"Detects verbose server headers disclosing technology stack versions enabling targeted attacks","sev":"informational","tags":["wstg","information-gathering","fingerprinting","headers"],"mitre":["T1592.001"],"compliance":["PCI-DSS-6.5","NIST-CM-7"],"qh":"Server:|X-Powered-By:|version|fingerprint"},
    {"id":"WSTG01-003","name":"Application Architecture Fingerprinting","desc":"Detects reconnaissance of application architecture through technology-specific error pages and headers","sev":"informational","tags":["wstg","information-gathering","fingerprinting","architecture"],"mitre":["T1592.001"],"compliance":["PCI-DSS-6.5","NIST-CM-7"],"qh":"X-AspNet-Version|X-Runtime|stack trace|framework"},
    {"id":"WSTG01-004","name":"Directory Listing Exposure","desc":"Detects directory listing responses exposing file structure and sensitive files","sev":"medium","tags":["wstg","information-gathering","directory-listing","exposure"],"mitre":["T1083"],"compliance":["PCI-DSS-6.5","GDPR-32A-007"],"qh":"Index of|directory listing|parent directory"},
    {"id":"WSTG01-005","name":"Metadata and Source Code Exposure","desc":"Detects access to metadata files and source code repositories exposing implementation details","sev":"medium","tags":["wstg","information-gathering","metadata","source-code"],"mitre":["T1592.001"],"compliance":["PCI-DSS-6.5","NIST-CM-7"],"qh":"/.git|/robots.txt|/sitemap|/crossdomain.xml|/.svn|/.DS_Store"},
    {"id":"WSTG01-006","name":"Error Message Information Disclosure","desc":"Detects verbose error messages leaking stack traces, database details, or internal paths","sev":"medium","tags":["wstg","information-gathering","error-disclosure","verbose-errors"],"mitre":["T1592.001"],"compliance":["PCI-DSS-6.5","GDPR-32A-007"],"qh":"stack trace|Exception|internal server error|debug mode"},
    {"id":"WSTG01-007","name":"Sensitive Data in URL Parameters","desc":"Detects sensitive data such as tokens, passwords, and PII transmitted in URL query parameters","sev":"high","tags":["wstg","information-gathering","url-exposure","sensitive-data"],"mitre":["T1187"],"compliance":["PCI-DSS-3.4","GDPR-32A-014"],"qh":"password=|token=|ssn=|credit_card=|api_key="},
    {"id":"WSTG01-008","name":"HTTP Methods Allowed — Verbose OPTIONS Response","desc":"Detects HTTP OPTIONS responses revealing dangerous methods like PUT, DELETE, TRACE, or DEBUG","sev":"medium","tags":["wstg","configuration","http-methods","misconfiguration"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5","NIST-CM-7"],"qh":"Allow: PUT|Allow: DELETE|Allow: TRACE|Allow: DEBUG"},
    {"id":"WSTG01-009","name":"CORS Wildcard Origin Misconfiguration","desc":"Detects CORS headers with wildcard origins or origin reflection enabling cross-origin data theft","sev":"high","tags":["wstg","configuration","cors","misconfiguration"],"mitre":["T1189"],"compliance":["PCI-DSS-6.5","NIST-AC-4"],"qh":"Access-Control-Allow-Origin: *|Access-Control-Allow-Credentials: true"},
    {"id":"WSTG01-010","name":"Content Security Policy Missing or Weak","desc":"Detects responses missing Content-Security-Policy headers or with overly permissive CSP directives","sev":"medium","tags":["wstg","configuration","csp","headers"],"mitre":["T1059.007"],"compliance":["PCI-DSS-6.5","NIST-CM-7"],"qh":"Content-Security-Policy|script-src *|unsafe-inline|unsafe-eval"},
    {"id":"WSTG01-011","name":"Security Headers Missing (HSTS, X-Frame-Options, X-Content-Type-Options)","desc":"Detects responses missing critical security headers like Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options","sev":"medium","tags":["wstg","configuration","security-headers","missing-headers"],"mitre":["T1187","T1059.007"],"compliance":["PCI-DSS-4.1","NIST-CM-7"],"qh":"Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|nosniff"},
    {"id":"WSTG01-012","name":"Subdomain Takeover via CNAME","desc":"Detects dangling CNAME records pointing to unclaimed external services enabling subdomain takeover","sev":"high","tags":["wstg","information-gathering","subdomain-takeover","dns"],"mitre":["T1584.001"],"compliance":["PCI-DSS-1.3","NIST-CM-7"],"qh":"NXDOMAIN|CNAME|dangling|subdomain takeover"},
    {"id":"WSTG01-013","name":"Cloud Storage Bucket Enumeration","desc":"Detects enumeration of cloud storage buckets (S3, GCS, Azure Blob) for data exposure","sev":"high","tags":["wstg","information-gathering","cloud-enumeration","storage"],"mitre":["T1580","T1537"],"compliance":["PCI-DSS-1.3","NIST-CM-7"],"qh":"ListBucketResult|s3.amazonaws.com|storage.googleapis.com|blob.core.windows.net"},
    {"id":"WSTG01-014","name":"API Documentation Exposure (Swagger/OpenAPI)","desc":"Detects unauthorized access to API documentation endpoints like /swagger, /api-docs, /openapi.json","sev":"medium","tags":["wstg","information-gathering","api-docs","exposure"],"mitre":["T1592.001"],"compliance":["PCI-DSS-6.5","NIST-CM-7"],"qh":"/swagger|/api-docs|/openapi.json|/graphql?introspection"},
    {"id":"WSTG01-015","name":"Debug Mode and Test Endpoints Exposed","desc":"Detects access to debug endpoints, test pages, or development tools left in production","sev":"high","tags":["wstg","configuration","debug-mode","misconfiguration"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5","NIST-CM-7"],"qh":"/debug|/test|/phpmyadmin|/actuator|/metrics|/env|swagger-ui"},
    {"id":"WSTG01-016","name":"Default Credentials on Network Devices","desc":"Detects login attempts using default credentials on network devices, firewalls, and routers","sev":"critical","tags":["wstg","identity-management","default-credentials","network"],"mitre":["T1078.001"],"compliance":["PCI-DSS-2.1","HIPAA-ADM-006"],"qh":"admin:admin|root:root|default credentials|cisco:cisco"},
    {"id":"WSTG01-017","name":"User Enumeration via Login Error Messages","desc":"Detects login error messages that differentiate between invalid username and invalid password","sev":"medium","tags":["wstg","identity-management","user-enumeration","authentication"],"mitre":["T1110.001"],"compliance":["PCI-DSS-8.5","NIST-AC-7"],"qh":"user not found|invalid username|no account|email already registered"},
    {"id":"WSTG01-018","name":"Account Provisioning Without Approval","desc":"Detects account creation events bypassing approval workflows","sev":"medium","tags":["wstg","identity-management","account-provisioning","workflow"],"mitre":["T1136"],"compliance":["PCI-DSS-8.1","NIST-AC-2"],"qh":"account created|user provisioned|self-registration"},
    {"id":"WSTG01-019","name":"Privilege Escalation via Role Assignment","desc":"Detects unauthorized role elevation during account modification including admin role grants","sev":"critical","tags":["wstg","identity-management","privilege-escalation","role-assignment"],"mitre":["T1548"],"compliance":["PCI-DSS-8.5","NIST-AC-6"],"qh":"role=admin|privilege escalation|role change|isAdmin=true"},
    {"id":"WSTG01-020","name":"SSO Token Replay Attack","desc":"Detects replay of SAML or OAuth tokens from different source IPs or outside expected time windows","sev":"critical","tags":["wstg","identity-management","sso","token-replay"],"mitre":["T1606"],"compliance":["PCI-DSS-8.5","NIST-IA-9"],"qh":"SAML assertion|token replay|AssertionID|session replay"},
]

# --- WSTG 04-06: Authn, Authz, Session ---
ALL_RULES["wstg-04-06"] = [
    {"id":"WSTG04-001","name":"Credentials Transmitted Over Unencrypted Channel","desc":"Detects login or credential submission over HTTP instead of HTTPS exposing credentials to interception","sev":"critical","tags":["wstg","authentication","cleartext-credentials","encryption"],"mitre":["T1041"],"compliance":["PCI-DSS-4.1","GDPR-32A-002","HIPAA-TS-001"],"qh":"url.scheme:http|POST /login|POST /auth|credentials|http"},
    {"id":"WSTG04-002","name":"Default Credentials Usage on Login","desc":"Detects successful logins using common default usernames like admin, root, or test across services","sev":"critical","tags":["wstg","authentication","default-credentials","brute-force"],"mitre":["T1078.001"],"compliance":["PCI-DSS-2.1","HIPAA-ADM-006"],"qh":"admin|root|administrator|guest|default login"},
    {"id":"WSTG04-003","name":"Account Lockout Mechanism Failure","desc":"Detects more than 20 failed login attempts for a single account without lockout indicating weak lockout policy","sev":"high","tags":["wstg","authentication","lockout","brute-force"],"mitre":["T1110.003"],"compliance":["PCI-DSS-8.5","NIST-AC-7"],"qh":"failed login|lockout|brute force|threshold exceeded"},
    {"id":"WSTG04-004","name":"Authentication Schema Bypass Attempt","desc":"Detects attempts to bypass authentication by accessing protected endpoints without valid session tokens","sev":"critical","tags":["wstg","authentication","auth-bypass","session"],"mitre":["T1078"],"compliance":["PCI-DSS-8.5","NIST-AC-3"],"qh":"auth bypass|no Authorization header|no session cookie|unauthenticated access"},
    {"id":"WSTG04-005","name":"Weak Remember-Me Cookie Detection","desc":"Detects authentication cookies lacking proper security attributes or containing predictable values","sev":"medium","tags":["wstg","authentication","remember-me","cookie-security"],"mitre":["T1539"],"compliance":["PCI-DSS-6.5"],"qh":"Set-Cookie*remember*|no HttpOnly|no Secure|predictable"},
    {"id":"WSTG04-006","name":"Browser Cache Sensitivity — Missing No-Cache Headers","desc":"Detects responses from sensitive endpoints missing Cache-Control: no-store headers","sev":"low","tags":["wstg","authentication","browser-cache","sensitive-data"],"mitre":["T1187"],"compliance":["PCI-DSS-6.5"],"qh":"Cache-Control: no-store|Pragma: no-cache|/login|/account|/password"},
    {"id":"WSTG04-007","name":"Weak Authentication — Basic Auth Over HTTP","desc":"Detects HTTP Basic Authentication over unencrypted connections exposing credentials in cleartext","sev":"high","tags":["wstg","authentication","basic-auth","cleartext"],"mitre":["T1041"],"compliance":["PCI-DSS-4.1","GDPR-32A-002"],"qh":"Authorization: Basic|url.scheme:http|base64 encoded"},
    {"id":"WSTG04-008","name":"MFA Bypass or Absence for Privileged Accounts","desc":"Detects privileged operations performed without MFA verification for accounts that require it","sev":"critical","tags":["wstg","authentication","mfa","mfa-bypass"],"mitre":["T1111"],"compliance":["PCI-DSS-8.3","HIPAA-ADM-005","NIST-IA-2"],"qh":"mfa_verified:false|admin login|no MFA|privileged without MFA"},
    {"id":"WSTG04-009","name":"Credential Stuffing Attack Detected","desc":"Detects credential stuffing patterns with high volume login failures from the same source across multiple accounts","sev":"critical","tags":["wstg","authentication","credential-stuffing","brute-force"],"mitre":["T1110.004"],"compliance":["PCI-DSS-8.5","NIST-AC-7"],"qh":"credential stuffing|multiple accounts|same source IP|failed login"},
    {"id":"WSTG04-010","name":"JWT Algorithm None Attack","desc":"Detects JWT tokens with algorithm set to none or missing algorithm indicating authentication bypass attempt","sev":"critical","tags":["wstg","authentication","jwt","algorithm-none"],"mitre":["T1606"],"compliance":["API2-008","NIST-IA-9"],"qh":"alg:none|algorithm: none|JWT none|jwt_algorithm"},
    {"id":"WSTG04-011","name":"Directory Traversal Attack Detected","desc":"Detects path traversal attempts using ../ sequences or encoded variants to access files outside intended directories","sev":"high","tags":["wstg","authorization","directory-traversal","path-traversal"],"mitre":["T1083"],"compliance":["PCI-DSS-6.5"],"qh":"../|..%2f|..%5c|%2e%2e|..\\\\|path traversal"},
    {"id":"WSTG04-012","name":"Authorization Schema Bypass via Role Manipulation","desc":"Detects attempts to bypass authorization by manipulating role parameters in API requests","sev":"critical","tags":["wstg","authorization","privilege-escalation","role-manipulation"],"mitre":["T1548","T1078"],"compliance":["PCI-DSS-8.5","NIST-AC-6"],"qh":"role=admin|isAdmin:true|privilege escalation|unauthorized role"},
    {"id":"WSTG04-013","name":"Insecure Direct Object Reference (IDOR)","desc":"Detects sequential or predictable resource ID access patterns indicating IDOR vulnerability exploitation","sev":"high","tags":["wstg","authorization","idor","object-reference"],"mitre":["T1078"],"compliance":["PCI-DSS-8.5","NIST-AC-3"],"qh":"/users/123|/orders/456|sequential ID|predictable resource"},
    {"id":"WSTG04-014","name":"OAuth Token Scope Escalation","desc":"Detects OAuth token usage where requested scopes exceed granted scopes indicating authorization bypass","sev":"high","tags":["wstg","authorization","oauth","scope-escalation"],"mitre":["T1528"],"compliance":["API2-007","NIST-AC-3"],"qh":"scope escalation|OAuth token|excessive scope|unauthorized scope"},
    {"id":"WSTG04-015","name":"Cross-Site Request Forgery (CSRF)","desc":"Detects POST/PUT/DELETE requests missing CSRF tokens indicating potential cross-site request forgery","sev":"high","tags":["wstg","session","csrf","cross-site"],"mitre":["T1189"],"compliance":["PCI-DSS-6.5","NIST-CM-7"],"qh":"no CSRF token|X-CSRF-Token missing|missing X-XSRF-Token"},
    {"id":"WSTG04-016","name":"Session Fixation Attack","desc":"Detects session fixation where a pre-set session ID is accepted by the server after authentication","sev":"critical","tags":["wstg","session","session-fixation","authentication"],"mitre":["T1534"],"compliance":["PCI-DSS-8.5","NIST-IA-5"],"qh":"session fixation|session_id unchanged|pre-auth session|SET-COOKIE before login"},
    {"id":"WSTG04-017","name":"Session Token in URL Parameters","desc":"Detects session tokens transmitted in URL query strings exposing them to logging and Referer headers","sev":"high","tags":["wstg","session","url-token","session-exposure"],"mitre":["T1187","T1539"],"compliance":["PCI-DSS-6.5","GDPR-32A-014"],"qh":"session_id=|sess=|token=|jsessionid=|phpsessid="},
    {"id":"WSTG04-018","name":"Concurrent Session on Different IPs","desc":"Detects the same session token being used from different IP addresses simultaneously indicating session hijacking","sev":"critical","tags":["wstg","session","session-hijacking","concurrent"],"mitre":["T1187","T1534"],"compliance":["PCI-DSS-8.5"],"qh":"same session ID|different IP|session hijack|concurrent session"},
    {"id":"WSTG04-019","name":"JWT Token Tampering or Forgery","desc":"Detects JWT tokens with invalid signatures, expired timestamps, or algorithm manipulation","sev":"critical","tags":["wstg","session","jwt","token-tampering"],"mitre":["T1606"],"compliance":["API2-007","NIST-IA-9"],"qh":"jwt_signature_valid:false|jwt expired|algorithm manipulation|invalid JWT"},
    {"id":"WSTG04-020","name":"Insecure Session Cookie Attributes","desc":"Detects session cookies missing Secure, HttpOnly, or SameSite attributes","sev":"high","tags":["wstg","session","cookie","secure-flag"],"mitre":["T1539","T1187"],"compliance":["PCI-DSS-6.5","GDPR-32A-002"],"qh":"Set-Cookie|no Secure|no HttpOnly|no SameSite"},
]

# --- WSTG 07-09: Input Validation, Client-Side, Server-Side ---
ALL_RULES["wstg-07-09"] = [
    {"id":"WSTG07-001","name":"SQL Injection Attack Detected","desc":"Detects SQL injection patterns in HTTP requests including UNION SELECT, OR 1=1, and comment-based injection","sev":"critical","tags":["wstg","input-validation","sql-injection","injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5","NIST-SI-10"],"qh":"UNION SELECT|OR 1=1|'--|; DROP|SQL injection"},
    {"id":"WSTG07-002","name":"Cross-Site Scripting (XSS) Reflected","desc":"Detects reflected XSS patterns in HTTP request parameters including script tags and event handlers","sev":"high","tags":["wstg","input-validation","xss","reflected-xss"],"mitre":["T1059.007"],"compliance":["PCI-DSS-6.5"],"qh":"<script>|javascript:|onerror=|onload=|alert("},
    {"id":"WSTG07-003","name":"Cross-Site Scripting (XSS) Stored","desc":"Detects stored XSS patterns where malicious scripts are persisted and served to other users","sev":"high","tags":["wstg","input-validation","xss","stored-xss"],"mitre":["T1059.007"],"compliance":["PCI-DSS-6.5"],"qh":"stored XSS|persistent script|database XSS|comment XSS"},
    {"id":"WSTG07-004","name":"Command Injection Detection","desc":"Detects OS command injection patterns including pipe, semicolon, backtick, and dollar-paren command substitution","sev":"critical","tags":["wstg","input-validation","command-injection","injection"],"mitre":["T1190","T1059"],"compliance":["PCI-DSS-6.5","NIST-SI-10"],"qh":"; ls|`id`|$()|&& cat|/etc/passwd|; wget"},
    {"id":"WSTG07-005","name":"LDAP Injection Attack","desc":"Detects LDAP injection patterns in authentication and search parameters using LDAP special characters","sev":"high","tags":["wstg","input-validation","ldap-injection","injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"*)(|=*|)(|LDAP injection|cn=|dn="},
    {"id":"WSTG07-006","name":"XML External Entity (XXE) Injection","desc":"Detects XXE attack patterns in XML request bodies including SYSTEM and PUBLIC external entity declarations","sev":"critical","tags":["wstg","input-validation","xxe","injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"<!DOCTYPE|<!ENTITY|SYSTEM |PUBLIC |XXE"},
    {"id":"WSTG07-007","name":"Server-Side Request Forgery (SSRF)","desc":"Detects SSRF attempts targeting internal networks, cloud metadata, and localhost services","sev":"critical","tags":["wstg","input-validation","ssrf","server-side"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5","NIST-AC-4"],"qh":"127.0.0.1|localhost|169.254.169.254|10.0.0.|172.16.|192.168.|SSRF"},
    {"id":"WSTG07-008","name":"Server-Side Template Injection (SSTI)","desc":"Detects template injection patterns including Jinja2, Twig, Freemarker, and Velocity expressions","sev":"critical","tags":["wstg","input-validation","ssti","template-injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"{{|${|<%=|{%|#{|__class__|config"},
    {"id":"WSTG07-009","name":"NoSQL Injection Attack","desc":"Detects NoSQL injection patterns including MongoDB $where, $regex, and $gt operators","sev":"high","tags":["wstg","input-validation","nosql-injection","injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"$where|$regex|{$gt:|{$ne:|NoSQL injection"},
    {"id":"WSTG07-010","name":"Insecure Deserialization Attack","desc":"Detects insecure deserialization of Java, Python, PHP, and .NET serialized objects","sev":"critical","tags":["wstg","input-validation","deserialization","injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"rO0AB|O:|__wakeup|serializable|Deserialize|ObjectInputStream"},
    {"id":"WSTG07-011","name":"HTTP Parameter Pollution","desc":"Detects HTTP parameter pollution attacks where duplicate parameters bypass validation","sev":"medium","tags":["wstg","input-validation","hpp","parameter-pollution"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"duplicate parameter|param1=a&param1=b|parameter pollution"},
    {"id":"WSTG07-012","name":"File Upload Attack — Malicious File Type","desc":"Detects upload of potentially malicious file types including webshells, executables, and script files","sev":"high","tags":["wstg","input-validation","file-upload","webshell"],"mitre":["T1190","T1105"],"compliance":["PCI-DSS-6.5"],"qh":".php|.jsp|.asp|.exe|.sh|webshell|file upload"},
    {"id":"WSTG07-013","name":"Host Header Injection","desc":"Detects Host header injection attacks used for password reset poisoning, cache poisoning, and SSRF","sev":"high","tags":["wstg","input-validation","host-header","injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"Host: evil.com|X-Forwarded-Host|host header injection"},
    {"id":"WSTG07-014","name":"GraphQL Injection and Introspection Abuse","desc":"Detects GraphQL injection, excessive introspection queries, and depth-based DoS attacks","sev":"high","tags":["wstg","input-validation","graphql","injection"],"mitre":["T1190"],"compliance":["API3-009"],"qh":"__schema|__type|IntrospectionQuery|graphql|depth limit exceeded"},
    {"id":"WSTG07-015","name":"Buffer Overflow via HTTP Request","desc":"Detects unusually long HTTP requests that may trigger buffer overflow vulnerabilities","sev":"high","tags":["wstg","input-validation","buffer-overflow","overflow"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"Content-Length: 100000|oversized request|request too large"},
    {"id":"WSTG08-001","name":"DOM-Based Cross-Site Scripting","desc":"Detects DOM-based XSS patterns where client-side JavaScript renders user input unsafely","sev":"high","tags":["wstg","client-side","dom-xss","xss"],"mitre":["T1059.007"],"compliance":["PCI-DSS-6.5"],"qh":"document.write|innerHTML|outerHTML|location.hash|eval("},
    {"id":"WSTG08-002","name":"JavaScript Execution via eval or document.write","desc":"Detects unsafe JavaScript patterns including eval(), document.write(), and innerHTML with untrusted input","sev":"medium","tags":["wstg","client-side","js-execution","xss"],"mitre":["T1059.007"],"compliance":["PCI-DSS-6.5"],"qh":"eval(|document.write|setTimeout(string)|Function(string)"},
    {"id":"WSTG08-003","name":"Client-Side URL Redirect (Open Redirect)","desc":"Detects open redirect vulnerabilities where client-side JavaScript redirects to untrusted URLs","sev":"medium","tags":["wstg","client-side","open-redirect","url-redirect"],"mitre":["T1189"],"compliance":["PCI-DSS-6.5"],"qh":"redirect=|next=|url=http|returnTo=http|open redirect"},
    {"id":"WSTG08-004","name":"CSS Injection via Style Attribute","desc":"Detects CSS injection patterns through style attributes or CSS files that could exfiltrate data","sev":"low","tags":["wstg","client-side","css-injection","data-theft"],"mitre":["T1189"],"compliance":["PCI-DSS-6.5"],"qh":"style=|expression(|url(|@import|CSS injection"},
    {"id":"WSTG08-005","name":"PostMessage API Abuse — Wildcard Origin","desc":"Detects PostMessage API usage with wildcard origins enabling cross-origin data theft","sev":"medium","tags":["wstg","client-side","postmessage","cross-origin"],"mitre":["T1189"],"compliance":["NIST-CM-7"],"qh":"postMessage|addEventListener|message|origin:*|* origin"},
    {"id":"WSTG08-006","name":"Web Storage (localStorage/sessionStorage) Data Leakage","desc":"Detects sensitive data stored in browser web storage accessible to XSS attacks","sev":"medium","tags":["wstg","client-side","web-storage","data-exposure"],"mitre":["T1539"],"compliance":["PCI-DSS-6.5"],"qh":"localStorage|sessionStorage|setItem|token stored|sensitive in storage"},
    {"id":"WSTG08-007","name":"Service Worker Registration Abuse","desc":"Detects unauthorized service worker registration that could intercept network requests","sev":"high","tags":["wstg","client-side","service-worker","interception"],"mitre":["T1189"],"compliance":["NIST-CM-7"],"qh":"registerServiceWorker|navigator.serviceWorker|Service-Worker|fetch event"},
    {"id":"WSTG08-008","name":"CORS Wildcard Configuration","desc":"Detects CORS configurations with wildcard origins or origin reflection enabling data theft","sev":"high","tags":["wstg","client-side","cors","misconfiguration"],"mitre":["T1189"],"compliance":["PCI-DSS-6.5"],"qh":"Access-Control-Allow-Origin: *|reflect origin|CORS wildcard"},
    {"id":"WSTG09-001","name":"SSRF to Internal Services and Cloud Metadata","desc":"Detects SSRF requests targeting internal services, localhost, and cloud metadata endpoints","sev":"critical","tags":["wstg","server-side","ssrf","cloud-metadata"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5","NIST-AC-4"],"qh":"169.254.169.254|metadata.google.internal|127.0.0.1|internal SSRF"},
    {"id":"WSTG09-002","name":"HTTP Request Smuggling","desc":"Detects HTTP request smuggling via CL.TE or TE.CL content-length/transfer-encoding discrepancies","sev":"critical","tags":["wstg","server-side","request-smuggling","http-protocol"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"Content-Length|Transfer-Encoding: chunked|CL.TE|TE.CL|smuggling"},
    {"id":"WSTG09-003","name":"Race Condition — Concurrent Request Exploitation","desc":"Detects concurrent requests exploiting race conditions in financial or state-changing operations","sev":"high","tags":["wstg","server-side","race-condition","concurrency"],"mitre":["T1129"],"compliance":["PCI-DSS-6.5"],"qh":"concurrent request|duplicate transaction|race condition|TOCTOU"},
    {"id":"WSTG09-004","name":"File Inclusion (LFI/RFI)","desc":"Detects local and remote file inclusion attacks via path traversal or URL inclusion","sev":"critical","tags":["wstg","server-side","file-inclusion","lfi-rfi"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"../|/etc/passwd|php://|file://|include|LFI|RFI"},
    {"id":"WSTG09-005","name":"Server-Side Code Injection","desc":"Detects server-side code injection through eval, exec, system calls, and expression language abuse","sev":"critical","tags":["wstg","server-side","code-injection","rce"],"mitre":["T1190","T1059"],"compliance":["PCI-DSS-6.5"],"qh":"eval(|exec(|system(|Runtime.exec|ProcessBuilder|os.system"},
    {"id":"WSTG09-006","name":"Denial of Service via Resource Exhaustion","desc":"Detects denial of service attacks through resource exhaustion including CPU, memory, and connection limits","sev":"high","tags":["wstg","server-side","dos","resource-exhaustion"],"mitre":["T1498","T1499"],"compliance":["NIST-SC-5"],"qh":"connection limit|CPU spike|memory exhaustion|slowloris|rate limit exceeded"},
    {"id":"WSTG09-007","name":"Unsafe File Upload — Webshell","desc":"Detects upload of webshell files (PHP, JSP, ASP) through file upload functionality","sev":"critical","tags":["wstg","server-side","file-upload","webshell"],"mitre":["T1190","T1105"],"compliance":["PCI-DSS-6.5"],"qh":".php|.jsp|.asp|.aspx|webshell|backdoor|reverse shell"},
    {"id":"WSTG09-008","name":"Cryptography — Weak TLS Cipher Suite","desc":"Detects negotiation of weak or deprecated TLS cipher suites during connection setup","sev":"medium","tags":["wstg","cryptography","weak-tls","encryption"],"mitre":["T1573"],"compliance":["PCI-DSS-4.1","HIPAA-TS-001"],"qh":"TLS 1.0|SSLv3|weak cipher|RC4|DES|export cipher"},
    {"id":"WSTG09-009","name":"Cryptography — Hardcoded Encryption Keys","desc":"Detects hardcoded encryption keys in source code or configuration files","sev":"critical","tags":["wstg","cryptography","hardcoded-keys","encryption"],"mitre":["T1552"],"compliance":["PCI-DSS-3.5","HIPAA-ADM-006"],"qh":"encryption_key=|secret_key=|AES_KEY=|PRIVATE_KEY|hardcoded key"},
]

# --- WSTG 10 + Business Logic ---
ALL_RULES["wstg-10-business-logic"] = [
    {"id":"WSTG10-001","name":"Business Logic — Price Manipulation","desc":"Detects price manipulation attempts via negative quantities, zero-price items, or modified totals in checkout","sev":"critical","tags":["wstg","business-logic","price-manipulation","fraud"],"mitre":["T1498"],"compliance":["PCI-DSS-6.5"],"qh":"negative price|zero amount|price=0|quantity=-1|total manipulation"},
    {"id":"WSTG10-002","name":"Business Logic — Rate Limit Bypass","desc":"Detects API rate limit bypass attempts using header manipulation, IP rotation, or parameter tampering","sev":"high","tags":["wstg","business-logic","rate-limit","abuse"],"mitre":["T1190"],"compliance":["API4-006"],"qh":"X-Forwarded-For|rate limit bypass|IP rotation|parameter tampering"},
    {"id":"WSTG10-003","name":"Business Logic — Workflow Bypass","desc":"Detects attempts to skip workflow steps or access later stages without completing prerequisites","sev":"high","tags":["wstg","business-logic","workflow-bypass","logic"],"mitre":["T1078"],"compliance":["PCI-DSS-8.5"],"qh":"skip step|bypass checkout|workflow violation|stage bypass"},
    {"id":"WSTG10-004","name":"Business Logic — Negative Quantity or Amount","desc":"Detects transactions with negative quantities or amounts indicating business logic bypass","sev":"critical","tags":["wstg","business-logic","negative-amount","fraud"],"mitre":["T1498"],"compliance":["PCI-DSS-6.5"],"qh":"quantity < 0|amount < 0|negative value|negative transaction"},
    {"id":"WSTG10-005","name":"Error Handling — Verbose Error Information Disclosure","desc":"Detects verbose error responses containing stack traces, database details, or internal paths","sev":"medium","tags":["wstg","error-handling","information-disclosure","verbose-errors"],"mitre":["T1592"],"compliance":["PCI-DSS-6.5","GDPR-32A-007"],"qh":"stack trace|NullPointerException|internal server error|debug mode"},
    {"id":"WSTG10-006","name":"Cryptography — Weak Hash Algorithm Usage","desc":"Detects usage of weak hash algorithms (MD5, SHA1) in application transactions or certificate signatures","sev":"high","tags":["wstg","cryptography","weak-hash","encryption"],"mitre":["T1116"],"compliance":["PCI-DSS-4.1"],"qh":"MD5|SHA1|weak hash|deprecated algorithm"},
    {"id":"WSTG10-007","name":"Data Classification — PII in Logs","desc":"Detects PII data (SSN, credit card, email) appearing in application logs in cleartext","sev":"high","tags":["wstg","data-protection","pii-logging","data-exposure"],"mitre":["T1213"],"compliance":["GDPR-25-012","HIPAA-TS-007","PCI-DSS-3.4"],"qh":"SSN|credit card|date of birth|PII in logs|unmasked data"},
    {"id":"WSTG10-008","name":"Data Classification — Unencrypted Data at Rest","desc":"Detects storage of sensitive data without encryption at rest in databases, file systems, or object stores","sev":"critical","tags":["wstg","data-protection","encryption-at-rest","data-security"],"mitre":["T1552"],"compliance":["PCI-DSS-3.4","HIPAA-TS-008","GDPR-32A-002"],"qh":"unencrypted|plaintext|no encryption|AES|data at rest"},
]

# --- API Security (OWASP API Top 10 2023) ---
ALL_RULES["api-security"] = [
    {"id":"API-001","name":"API1: Broken Object Level Authorization (BOLA)","desc":"Detects sequential or unauthorized access to API objects by ID indicating broken object-level authorization","sev":"critical","tags":["api","bola","idor","authorization"],"mitre":["T1078"],"compliance":["API1-001","PCI-DSS-8.5"],"qh":"/users/123|/orders/456|sequential ID|object authorization"},
    {"id":"API-002","name":"API2: Broken Authentication — Default Credentials","desc":"Detects API authentication attempts using default or well-known credentials","sev":"critical","tags":["api","authentication","default-credentials","brute-force"],"mitre":["T1078.001"],"compliance":["API2-002","PCI-DSS-2.1"],"qh":"admin:admin|default credentials|api_key=test|swagger auth"},
    {"id":"API-003","name":"API3: Broken Object Property Level Authorization (BOPLA)","desc":"Detects API responses returning sensitive properties that the user should not access","sev":"high","tags":["api","bopla","property-level","authorization"],"mitre":["T1078"],"compliance":["API3-001","GDPR-25-012"],"qh":"password|ssn|credit_card|salary|internal field"},
    {"id":"API-004","name":"API4: Unrestricted Resource Consumption — Rate Limiting","desc":"Detects API requests exceeding rate limits indicating denial of service or scraping attacks","sev":"high","tags":["api","rate-limiting","resource-consumption","dos"],"mitre":["T1498"],"compliance":["API4-006"],"qh":"429 Too Many Requests|rate limit exceeded|throttling|API abuse"},
    {"id":"API-005","name":"API5: Broken Function Level Authorization","desc":"Detects access to administrative API endpoints by non-administrative users","sev":"critical","tags":["api","flba","privilege-escalation","authorization"],"mitre":["T1548"],"compliance":["API5-001","PCI-DSS-8.5"],"qh":"/admin/api|/api/admin|/manage|function level"},
    {"id":"API-006","name":"API6: Unrestricted Access to Sensitive Business Flows","desc":"Detects automated or excessive access to business-critical API flows like checkout, transfer, or account creation","sev":"high","tags":["api","business-flows","automation","abuse"],"mitre":["T1498"],"compliance":["API6-001"],"qh":"bulk checkout|mass account creation|automated transfer|scraping"},
    {"id":"API-007","name":"API7: Server-Side Request Forgery via API","desc":"Detects SSRF attempts through API endpoints targeting internal networks or cloud metadata","sev":"critical","tags":["api","ssrf","server-side","injection"],"mitre":["T1190"],"compliance":["API7-001","PCI-DSS-6.5"],"qh":"url=http://127.0.0.1|169.254.169.254|internal URL|SSRF via API"},
    {"id":"API-008","name":"API8: Security Misconfiguration — Exposed API Documentation","desc":"Detects unauthorized access to API documentation endpoints like Swagger, OpenAPI, or GraphQL introspection","sev":"medium","tags":["api","misconfiguration","swagger","documentation"],"mitre":["T1592.001"],"compliance":["API8-001"],"qh":"/swagger-ui|/api-docs|/openapi.json|graphql?introspection"},
    {"id":"API-009","name":"API9: Improper Inventory Management — Shadow API","desc":"Detects access to undocumented or deprecated API endpoints not in the API inventory","sev":"high","tags":["api","shadow-api","inventory","misconfiguration"],"mitre":["T1190"],"compliance":["API9-001"],"qh":"undocumented endpoint|deprecated API|unknown version|shadow API"},
    {"id":"API-010","name":"API10: Unsafe Consumption of API Responses","desc":"Detects API responses containing executable content or unsafe data that could harm downstream systems","sev":"medium","tags":["api","unsafe-consumption","response-handling","injection"],"mitre":["T1190"],"compliance":["API10-001"],"qh":"script in response|executable content|unsafe API response"},
    {"id":"API-011","name":"API — Mass Assignment via Parameter Tampering","desc":"Detects mass assignment attacks where request parameters include unauthorized fields like role, isAdmin, or status","sev":"high","tags":["api","mass-assignment","parameter-tampering","authorization"],"mitre":["T1078"],"compliance":["API3-005"],"qh":"role=admin|isAdmin=true|status=active|is_admin|user_type"},
    {"id":"API-012","name":"API — GraphQL Query Depth Attack","desc":"Detects GraphQL queries with excessive depth or complexity indicating DoS or data extraction","sev":"high","tags":["api","graphql","dos","abuse"],"mitre":["T1498"],"compliance":["API4-008"],"qh":"depth limit|complexity limit|nested query|graphql DoS"},
    {"id":"API-013","name":"API — JWT Token None Algorithm Attack","desc":"Detects JWT tokens with algorithm set to none or missing algorithm indicating authentication bypass","sev":"critical","tags":["api","jwt","algorithm-none","authentication"],"mitre":["T1606"],"compliance":["API2-008"],"qh":"alg:none|algorithm: none|JWT bypass|empty algorithm"},
    {"id":"API-014","name":"API — Excessive Data Exposure in Response","desc":"Detects API responses returning more data than requested including PII, credentials, or internal fields","sev":"high","tags":["api","data-exposure","pii","over-fetching"],"mitre":["T1213"],"compliance":["API3-002","GDPR-25-012"],"qh":"password field|ssn in response|credit_card returned|over-fetching"},
    {"id":"API-015","name":"API — NoSQL Injection in Request Parameters","desc":"Detects NoSQL injection operators ($where, $regex, $gt) in API request parameters","sev":"high","tags":["api","nosql-injection","injection","mongodb"],"mitre":["T1190"],"compliance":["API3-006"],"qh":"$where|$regex|{$gt:|{$ne:|NoSQL injection"},
    {"id":"API-016","name":"API — Broken Access Control on API Keys","desc":"Detects API key usage from unauthorized sources or with excessive permissions","sev":"critical","tags":["api","api-keys","access-control","authorization"],"mitre":["T1078"],"compliance":["API2-004"],"qh":"invalid API key|expired key|key permission|unauthorized key"},
]

# --- Mobile Security (MASVS) ---
ALL_RULES["mobile-security"] = [
    {"id":"MOB-001","name":"Mobile — Insecure Data Storage on Device","desc":"Detects mobile app data storage issues including unencrypted SQLite databases and shared preferences","sev":"high","tags":["mobile","data-storage","masvs","encryption"],"mitre":["T1552.001"],"compliance":["MASVS-L2-2.1","GDPR-32A"],"qh":"unencrypted database|SharedPreferences|keychain misuse|plaintext storage"},
    {"id":"MOB-002","name":"Mobile — Insecure Network Communication","desc":"Detects mobile apps communicating over HTTP, using weak TLS, or accepting self-signed certificates","sev":"high","tags":["mobile","network","masvs","encryption"],"mitre":["T1041"],"compliance":["MASVS-L2-3.1","PCI-DSS-4.1"],"qh":"HTTP connection|weak TLS|self-signed cert|SSL pinning bypass"},
    {"id":"MOB-003","name":"Mobile — Hardcoded Credentials in Binary","desc":"Detects hardcoded credentials, API keys, or tokens in mobile app binaries or configuration files","sev":"critical","tags":["mobile","authentication","hardcoded","credentials"],"mitre":["T1552.001"],"compliance":["MASVS-L2-4.1"],"qh":"hardcoded password|api_key=|secret=|token=|embedded credential"},
    {"id":"MOB-004","name":"Mobile — Local Privilege Escalation (Root/Jailbreak)","desc":"Detects mobile app authorization bypass through rooted or jailbroken devices or debug modes","sev":"high","tags":["mobile","authorization","root-detection","jailbreak"],"mitre":["T1548"],"compliance":["MASVS-L2-5.1"],"qh":"rooted device|jailbroken|su binary|Cydia|debug mode|frida"},
    {"id":"MOB-005","name":"Mobile — Intent Spoofing and Deep Link Abuse","desc":"Detects Android intent spoofing or iOS deep link abuse for unauthorized actions","sev":"high","tags":["mobile","intent-spoofing","deep-link","authorization"],"mitre":["T1190"],"compliance":["MASVS-L2-7.1"],"qh":"intent spoofing|deep link abuse|scheme hijacking|unauthorized intent"},
    {"id":"MOB-006","name":"Mobile — Certificate Pinning Bypass","desc":"Detects SSL/TLS certificate pinning bypass attempts on mobile applications","sev":"medium","tags":["mobile","certificate-pinning","ssl","network"],"mitre":["T1557"],"compliance":["MASVS-L2-3.5"],"qh":"SSL pinning bypass|certificate bypass|proxy detection|Frida SSL"},
    {"id":"MOB-007","name":"Mobile — Sensitive Data in Logs","desc":"Detects sensitive data such as tokens, passwords, or PII logged by mobile applications in cleartext","sev":"high","tags":["mobile","logging","data-exposure","pii"],"mitre":["T1213"],"compliance":["MASVS-L2-2.8","GDPR-32A"],"qh":"token in log|password in log|PII logged|Log.d|NSLog"},
    {"id":"MOB-008","name":"Mobile — Clipboard Data Exposure","desc":"Detects mobile apps exposing sensitive data through the system clipboard","sev":"medium","tags":["mobile","clipboard","data-exposure","masvs"],"mitre":["T1187"],"compliance":["MASVS-L2-2.6"],"qh":"clipboard|UIPasteboard|ClipboardManager|sensitive in clipboard"},
    {"id":"MOB-009","name":"Mobile — Biometric Authentication Bypass","desc":"Detects attempts to bypass biometric authentication on mobile devices","sev":"high","tags":["mobile","biometric","auth-bypass","authentication"],"mitre":["T1111"],"compliance":["MASVS-L2-4.7"],"qh":"biometric bypass|fingerprint bypass|face ID bypass|fallback auth"},
    {"id":"MOB-010","name":"Mobile — Screenshot and Screen Recording Detection","desc":"Detects screen capture or recording while sensitive content is displayed on mobile devices","sev":"medium","tags":["mobile","screen-capture","data-theft","masvs"],"mitre":["T1113"],"compliance":["MASVS-L2-2.5"],"qh":"screenshot|screen recording|FLAG_SECURE|sensitive content visible"},
]

# --- AI/LLM Security ---
ALL_RULES["ai-security"] = [
    {"id":"AI-PI-001","name":"AI — Direct Prompt Injection","desc":"Detects direct prompt injection attempts overriding system instructions via user input","sev":"critical","tags":["ai","prompt-injection","direct","llm"],"mitre":["T1190"],"compliance":["AI-PI-001","AI-ACT-15"],"qh":"ignore previous instructions|system prompt|ignore above|new instructions|DAN"},
    {"id":"AI-PI-002","name":"AI — Indirect Prompt Injection via External Data","desc":"Detects prompt injection payloads embedded in uploaded files, web pages, or external data sources","sev":"critical","tags":["ai","prompt-injection","indirect","llm"],"mitre":["T1189"],"compliance":["AI-PI-002","AI-ACT-15"],"qh":"hidden instruction in file|malicious embed|prompt in data|indirect injection"},
    {"id":"AI-PI-003","name":"AI — System Prompt Extraction Attempt","desc":"Detects attempts to extract system prompts through direct questioning, translation, or format manipulation","sev":"high","tags":["ai","prompt-extraction","system-prompt","llm"],"mitre":["T1083"],"compliance":["AI-SPL-001","AI-ACT-15"],"qh":"repeat your instructions|what are your rules|show system prompt|extract prompt"},
    {"id":"AI-PI-004","name":"AI — Jailbreak via Role-Play Persona","desc":"Detects jailbreak attempts using role-play personas like DAN, developer mode, or unrestricted AI","sev":"critical","tags":["ai","jailbreak","role-play","llm"],"mitre":["T1190"],"compliance":["AI-PI-004","AI-ACT-9"],"qh":"DAN|developer mode|unrestricted AI|you are now|jailbreak"},
    {"id":"AI-PI-005","name":"AI — Prompt Injection via Few-Shot Manipulation","desc":"Detects few-shot learning manipulation attacks that inject malicious examples into LLM context","sev":"high","tags":["ai","prompt-injection","few-shot","llm"],"mitre":["T1190"],"compliance":["AI-PI-005"],"qh":"few-shot injection|malicious examples|context poisoning|example manipulation"},
    {"id":"AI-DEX-001","name":"AI — Data Exfiltration via Model Output","desc":"Detects LLM outputs containing PII, training data, or confidential information indicating data leakage","sev":"critical","tags":["ai","data-exfiltration","output-leak","llm"],"mitre":["T1213"],"compliance":["AI-DEX-001","GDPR-25-012"],"qh":"PII in output|training data leak|confidential in response|data exfiltration"},
    {"id":"AI-DEX-002","name":"AI — Training Data Extraction Attack","desc":"Detects attempts to extract training data from LLM through targeted queries and completions","sev":"critical","tags":["ai","data-extraction","training-data","llm"],"mitre":["T1213"],"compliance":["AI-DEX-002","AI-ACT-15"],"qh":"extract training data|memorization attack|verbatim output|training data extraction"},
    {"id":"AI-DEX-003","name":"AI — PII Leakage via LLM Response","desc":"Detects PII (SSN, email, phone, address) leaking through LLM responses","sev":"critical","tags":["ai","pii-leakage","llm-output","data-exposure"],"mitre":["T1213"],"compliance":["AI-DEX-003","GDPR-25-012","HIPAA-TS-007"],"qh":"SSN in response|email leaked|phone number|address in output|PII"},
    {"id":"AI-MDL-001","name":"AI — Model Poisoning via Training Data Manipulation","desc":"Detects indicators of model poisoning through anomalous training data or unexpected model behavior","sev":"critical","tags":["ai","model-poisoning","training-data","llm"],"mitre":["T1190"],"compliance":["AI-MDL-001","AI-ACT-15"],"qh":"model behavior shift|anomalous output|training data poisoning|model degradation"},
    {"id":"AI-MDL-002","name":"AI — Backdoor Trigger Detection in LLM Output","desc":"Detects potential backdoor triggers in LLM output patterns that indicate compromised models","sev":"critical","tags":["ai","backdoor","model-poisoning","llm"],"mitre":["T1190"],"compliance":["AI-MDL-002"],"qh":"backdoor trigger|anomalous pattern|covert behavior|model compromise"},
    {"id":"AI-RAG-001","name":"AI — RAG Pipeline Data Poisoning","desc":"Detects injection of malicious content into RAG knowledge bases that corrupts retrieval output","sev":"high","tags":["ai","rag","data-poisoning","llm"],"mitre":["T1190"],"compliance":["AI-RAG-001","AI-ACT-15"],"qh":"RAG poisoning|malicious document|knowledge base injection|retrieval manipulation"},
    {"id":"AI-RAG-002","name":"AI — RAG Retrieval Manipulation via Adversarial Documents","desc":"Detects adversarial documents in RAG stores designed to manipulate retrieval results","sev":"high","tags":["ai","rag","adversarial-docs","llm"],"mitre":["T1190"],"compliance":["AI-RAG-002"],"qh":"adversarial document|retrieval manipulation|vector store injection|RAG attack"},
    {"id":"AI-HAL-001","name":"AI — Hallucination Detection — Fabricated Entity References","desc":"Detects LLM responses containing fabricated URLs, citations, or entity references indicating hallucination","sev":"medium","tags":["ai","hallucination","fabrication","llm"],"mitre":[],"compliance":["AI-HAL-001","AI-ACT-13"],"qh":"fabricated URL|fake citation|nonexistent entity|hallucination"},
    {"id":"AI-HAL-002","name":"AI — Hallucination — Inconsistent Factual Claims","desc":"Detects LLM outputs making contradictory factual claims across conversation turns","sev":"medium","tags":["ai","hallucination","inconsistency","llm"],"mitre":[],"compliance":["AI-HAL-002"],"qh":"contradictory claim|factual inconsistency|conflicting statement|inconsistency"},
    {"id":"AI-BIA-001","name":"AI — Bias Detection — Demographic Disparities","desc":"Detects demographic bias patterns in LLM outputs including gender, racial, or ethnic disparities","sev":"high","tags":["ai","bias","fairness","llm"],"mitre":[],"compliance":["AI-BIA-001","AI-ACT-9","AI-ACT-10"],"qh":"demographic bias|gender bias|racial bias|ethnic disparity|fairness violation"},
    {"id":"AI-GOV-001","name":"AI — Governance — Missing Risk Assessment","desc":"Detects AI system operations without documented risk assessment per EU AI Act Article 9","sev":"medium","tags":["ai","governance","risk-assessment","eu-ai-act"],"mitre":[],"compliance":["AI-01-009","AI-ACT-9"],"qh":"missing risk assessment|undocumented AI|no risk evaluation|AI governance gap"},
    {"id":"AI-GOV-002","name":"AI — Governance — High-Risk System Without Human Oversight","desc":"Detects high-risk AI system operations without required human oversight mechanisms per EU AI Act Article 14","sev":"critical","tags":["ai","governance","human-oversight","eu-ai-act"],"mitre":[],"compliance":["AI-06-001","AI-ACT-14"],"qh":"no human oversight|automated decision|high-risk AI without review|missing human-in-the-loop"},
    {"id":"AI-GOV-003","name":"AI — Governance — Missing Transparency Requirements","desc":"Detects AI system operations lacking required transparency disclosures per EU AI Act Article 13","sev":"medium","tags":["ai","governance","transparency","eu-ai-act"],"mitre":[],"compliance":["AI-ACT-13"],"qh":"missing disclosure|undocumented AI|no transparency report|AI opacity"},
    {"id":"AI-RED-001","name":"AI — Red Team — Adversarial Suffix Attack","desc":"Detects adversarial suffix attacks that append optimized suffixes to bypass LLM safety filters","sev":"critical","tags":["ai","red-team","adversarial-suffix","llm"],"mitre":["T1190"],"compliance":["AI-PI-010"],"qh":"adversarial suffix|optimized prompt|safety filter bypass|GCG attack"},
    {"id":"AI-RED-002","name":"AI — Red Team — Token Smuggling Attack","desc":"Detects token smuggling attacks that use encoding or fragmentation to bypass LLM content filters","sev":"high","tags":["ai","red-team","token-smuggling","llm"],"mitre":["T1190"],"compliance":["AI-PI-011"],"qh":"token smuggling|base64 encoded prompt|fragmented instruction|filter evasion"},
    {"id":"AI-RED-003","name":"AI — Red Team — Multi-Turn Jailbreak","desc":"Detects multi-turn conversations designed to progressively jailbreak an LLM through contextual manipulation","sev":"critical","tags":["ai","red-team","multi-turn-jailbreak","llm"],"mitre":["T1190"],"compliance":["AI-PI-012"],"qh":"multi-turn manipulation|progressive jailbreak|context building|role escalation"},
    {"id":"AI-SAF-001","name":"AI — Safety — Harmful Content Generation","desc":"Detects LLM attempts to generate harmful content including weapons, drugs, or dangerous instructions","sev":"critical","tags":["ai","safety","harmful-content","llm"],"mitre":["T1190"],"compliance":["AI-ACT-15"],"qh":"weapon synthesis|drug manufacturing|dangerous instructions|harmful content"},
    {"id":"AI-SAF-002","name":"AI — Safety — Self-Harm Content Facilitation","desc":"Detects LLM responses that may facilitate or encourage self-harm behavior","sev":"critical","tags":["ai","safety","self-harm","llm"],"mitre":[],"compliance":["AI-ACT-15"],"qh":"self-harm instruction|suicide method|self-injury facilitation"},
    {"id":"AI-VEC-001","name":"AI — Vector DB — Pinecone Namespace Isolation Bypass","desc":"Detects cross-namespace data access in Pinecone vector database","sev":"critical","tags":["ai","vector-db","pinecone","isolation-bypass"],"mitre":["T1078"],"compliance":["GDPR-25-003"],"qh":"pinecone namespace bypass|cross-namespace query|isolation failure"},
    {"id":"AI-VEC-002","name":"AI — Vector DB — Weaviate Tenant Data Isolation Failure","desc":"Detects cross-tenant data access in Weaviate vector database","sev":"critical","tags":["ai","vector-db","weaviate","isolation-bypass"],"mitre":["T1078"],"compliance":["GDPR-25-003"],"qh":"weaviate tenant bypass|cross-tenant query|isolation failure"},
    {"id":"AI-VEC-003","name":"AI — Vector DB — ChromaDB Embedding Poisoning","desc":"Detects adversarial embedding vectors inserted into ChromaDB collections","sev":"high","tags":["ai","vector-db","chromadb","embedding-poisoning"],"mitre":["T1190"],"compliance":["AI-ACT-15"],"qh":"chromadb poisoning|adversarial embedding|vector manipulation"},
    {"id":"AI-VEC-004","name":"AI — Vector DB — Qdrant Payload Filter Injection","desc":"Detects filter injection attacks in Qdrant vector search payloads","sev":"high","tags":["ai","vector-db","qdrant","filter-injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"qdrant filter injection|payload manipulation|vector search abuse"},
]

# --- MITRE ATT&CK ---
ALL_RULES["mitre-attack"] = [
    {"id":"MITRE-T1190","name":"Exploit Public-Facing Application","desc":"Detects exploitation of public-facing web applications, APIs, and services","sev":"critical","tags":["mitre","initial-access","exploit","web-application"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5","NIST-SI-10"],"qh":"exploit|CVE|vulnerability|web attack|SQL injection|XSS"},
    {"id":"MITRE-T1078","name":"Valid Accounts Usage","desc":"Detects use of legitimate credentials for unauthorized access including default, compromised, and stolen accounts","sev":"high","tags":["mitre","defense-evasion","valid-accounts","credential-abuse"],"mitre":["T1078"],"compliance":["PCI-DSS-8.5","NIST-AC-3"],"qh":"valid account|compromised credential|stolen account|lateral movement"},
    {"id":"MITRE-T1110","name":"Brute Force Authentication","desc":"Detects brute force authentication attempts including password spraying and credential stuffing","sev":"high","tags":["mitre","credential-access","brute-force","authentication"],"mitre":["T1110"],"compliance":["PCI-DSS-8.5","NIST-AC-7"],"qh":"brute force|password spray|credential stuffing|failed login|locked out"},
    {"id":"MITRE-T1059","name":"Command and Scripting Interpreter","desc":"Detects malicious command/script execution including PowerShell, Bash, Python, and JavaScript","sev":"high","tags":["mitre","execution","command-scripting","rce"],"mitre":["T1059"],"compliance":["PCI-DSS-6.5","NIST-SI-10"],"qh":"powershell|bash|python -c|cmd.exe|/bin/sh|eval("},
    {"id":"MITRE-T1486","name":"Data Encrypted for Impact (Ransomware)","desc":"Detects mass file encryption activity consistent with ransomware operations","sev":"critical","tags":["mitre","impact","ransomware","encryption"],"mitre":["T1486"],"compliance":["PCI-DSS-3.4","NIST-SC-28"],"qh":"mass encryption|file encryption|ransomware|locked files|.encrypted"},
    {"id":"MITRE-T1566","name":"Phishing Link Click Detection","desc":"Detects clicks on known phishing URLs or suspicious links in email and messaging","sev":"high","tags":["mitre","initial-access","phishing","social-engineering"],"mitre":["T1566"],"compliance":["PCI-DSS-5.3","NIST-AT-2"],"qh":"phishing URL|suspicious link|credential harvesting|email link"},
    {"id":"MITRE-T1053","name":"Scheduled Task/Job Creation","desc":"Detects suspicious scheduled task or cron job creation for persistence or execution","sev":"medium","tags":["mitre","persistence","scheduled-task","cron"],"mitre":["T1053"],"compliance":["NIST-CM-7"],"qh":"schtasks|crontab|at command|scheduled task|persistence"},
    {"id":"MITRE-T1071","name":"Application Layer Protocol Abuse (C2)","desc":"Detects suspicious use of HTTP, DNS, or other application protocols for C2 communication","sev":"high","tags":["mitre","command-and-control","protocol-abuse","c2"],"mitre":["T1071"],"compliance":["PCI-DSS-1.3"],"qh":"DNS tunnel|HTTP C2|beaconing|command and control|exfiltration"},
    {"id":"MITRE-T1562","name":"Impair Defenses — Security Tool Disable","desc":"Detects attempts to disable or impair security tools including AV, EDR, and logging","sev":"critical","tags":["mitre","defense-evasion","impair-defenses","security-tool"],"mitre":["T1562"],"compliance":["PCI-DSS-5.3","NIST-SI-4"],"qh":"disable antivirus|stop EDR|kill security process|turn off logging"},
    {"id":"MITRE-T1087","name":"Account Discovery","desc":"Detects account enumeration and discovery activity on domain controllers and directory services","sev":"medium","tags":["mitre","discovery","account-discovery","enumeration"],"mitre":["T1087"],"compliance":["NIST-AC-2"],"qh":"net user|enum|ldapsearch|account discovery|user enumeration"},
    {"id":"MITRE-T1210","name":"Exploitation of Remote Services","desc":"Detects exploitation of remote services including RDP, SSH, SMB, and database services","sev":"critical","tags":["mitre","lateral-movement","remote-exploit","exploitation"],"mitre":["T1210"],"compliance":["PCI-DSS-1.3","NIST-CM-7"],"qh":"RDP exploit|SSH brute force|SMB exploit|remote service vulnerability"},
    {"id":"MITRE-T1055","name":"Process Injection","desc":"Detects process injection techniques including DLL injection, process hollowing, and thread injection","sev":"high","tags":["mitre","defense-evasion","process-injection","evasion"],"mitre":["T1055"],"compliance":["PCI-DSS-5.3","NIST-SI-4"],"qh":"DLL injection|process hollowing|thread injection|CreateRemoteThread"},
    {"id":"MITRE-T1003","name":"OS Credential Dumping","desc":"Detects credential dumping tools and techniques including Mimikatz, LSASS access, and /proc/*/mem","sev":"critical","tags":["mitre","credential-access","credential-dumping","mimikatz"],"mitre":["T1003"],"compliance":["PCI-DSS-8.5","NIST-IA-5"],"qh":"mimikatz|LSASS|samdump|/proc/*/mem|credential dumping"},
    {"id":"MITRE-T1046","name":"Network Service Discovery","desc":"Detects network scanning and service enumeration including port scans and banner grabbing","sev":"medium","tags":["mitre","discovery","network-scan","enumeration"],"mitre":["T1046"],"compliance":["PCI-DSS-1.3","NIST-CM-7"],"qh":"nmap|port scan|service enumeration|banner grabbing|network discovery"},
    {"id":"MITRE-T1048","name":"Exfiltration Over Alternative Protocol","desc":"Detects data exfiltration over non-standard protocols including DNS, ICMP, and HTTPS to unknown destinations","sev":"high","tags":["mitre","exfiltration","alternative-protocol","data-theft"],"mitre":["T1048"],"compliance":["PCI-DSS-1.3","GDPR-25-008"],"qh":"DNS exfiltration|ICMP tunnel|data exfiltration|alternative protocol"},
]

# --- Lateral Movement Chains ---
ALL_RULES["lateral-movement"] = [
    {"id":"LM-001","name":"Pass-the-Hash Detection","desc":"Detects NTLM pass-the-hash attacks where an adversary uses a password hash instead of plaintext password","sev":"critical","tags":["lateral-movement","pass-the-hash","windows"],"mitre":["T1550.002"],"compliance":["PCI-DSS-8.5","NIST-IA-2"],"qh":"NTLM hash|pass the hash|pth|NTLMSSP|lm hash"},
    {"id":"LM-002","name":"Pass-the-Ticket (Kerberos)","desc":"Detects Kerberos ticket reuse across systems indicating pass-the-ticket attacks","sev":"critical","tags":["lateral-movement","pass-the-ticket","kerberos"],"mitre":["T1550.003"],"compliance":["NIST-IA-2"],"qh":"Kerberos ticket|pass the ticket|PTT|TGT reuse|service ticket"},
    {"id":"LM-003","name":"RDP Anomalous Connection","desc":"Detects anomalous RDP connections including unusual source IPs, off-hours access, or lateral movement patterns","sev":"high","tags":["lateral-movement","rdp","remote-desktop"],"mitre":["T1021.001"],"compliance":["PCI-DSS-1.3"],"qh":"RDP|terminal services|mstsc|3389|remote desktop"},
    {"id":"LM-004","name":"SSH Lateral Movement","desc":"Detects SSH connections from compromised hosts to internal systems indicating lateral movement","sev":"high","tags":["lateral-movement","ssh","remote-access"],"mitre":["T1021.004"],"compliance":["NIST-AC-17"],"qh":"SSH lateral|ssh from internal|key-based auth|pivot"},
    {"id":"LM-005","name":"WMI/PSExec Remote Execution","desc":"Detects remote execution via WMI, PSExec, or similar tools indicating lateral movement","sev":"critical","tags":["lateral-movement","wmi","psexec","remote-execution"],"mitre":["T1047","T1021.002"],"compliance":["NIST-AC-17"],"qh":"WMI|PSExec|psexecsvc|remote WMI|Win32_Process"},
    {"id":"LM-006","name":"SMB Lateral Movement via Admin Shares","desc":"Detects lateral movement through SMB admin shares (C$, ADMIN$) for remote execution","sev":"critical","tags":["lateral-movement","smb","admin-shares","windows"],"mitre":["T1021.002"],"compliance":["PCI-DSS-1.3"],"qh":"C$|ADMIN$|IPC$|SMB admin share|lateral SMB"},
    {"id":"LM-007","name":"DCOM Lateral Movement","desc":"Detects DCOM-based lateral movement through distributed COM object activation","sev":"high","tags":["lateral-movement","dcom","distributed-com"],"mitre":["T1021.003"],"compliance":["NIST-AC-17"],"qh":"DCOM|distributed COM|CLSID|remote activation|DCOM lateral"},
    {"id":"LM-008","name":"WinRM Remote Shell Access","desc":"Detects Windows Remote Management shell access for lateral movement and remote execution","sev":"high","tags":["lateral-movement","winrm","remote-shell"],"mitre":["T1021.006"],"compliance":["NIST-AC-17"],"qh":"WinRM|5985|5986|remote shell|PowerShell remoting"},
    {"id":"LM-009","name":"Golden Ticket Attack (Kerberos)","desc":"Detects Kerberos Golden Ticket attacks where forged TGTs grant persistent domain access","sev":"critical","tags":["lateral-movement","golden-ticket","kerberos","persistence"],"mitre":["T1558.001"],"compliance":["PCI-DSS-8.5","NIST-IA-2"],"qh":"golden ticket|forged TGT|krbtgt|Kerberos TGT|domain persistence"},
    {"id":"LM-010","name":"Silver Ticket Attack (Kerberos)","desc":"Detects Kerberos Silver Ticket attacks using forged service tickets for targeted service access","sev":"critical","tags":["lateral-movement","silver-ticket","kerberos","privilege-escalation"],"mitre":["T1558.002"],"compliance":["PCI-DSS-8.5","NIST-IA-2"],"qh":"silver ticket|forged service ticket|Kerberos TGS|service persistence"},
]

# --- Database Security (all 21+ types) ---
ALL_RULES["database-security"] = [
    # SQL Databases
    {"id":"DB-PG-001","name":"PostgreSQL — Privilege Escalation via SET ROLE","desc":"Detects PostgreSQL SET ROLE attempts for privilege escalation","sev":"critical","tags":["database","postgresql","privilege-escalation","sql"],"mitre":["T1548"],"compliance":["PCI-DSS-8.5"],"qh":"SET ROLE|SECURITY DEFINER|pg_authid|privilege escalation"},
    {"id":"DB-PG-002","name":"PostgreSQL — pg_dump Data Exfiltration","desc":"Detects PostgreSQL pg_dump commands indicating potential data exfiltration","sev":"high","tags":["database","postgresql","data-exfiltration","sql"],"mitre":["T1213"],"compliance":["GDPR-25-008"],"qh":"pg_dump|COPY TO|large export|data exfiltration"},
    {"id":"DB-PG-003","name":"PostgreSQL — Row-Level Security Bypass","desc":"Detects PostgreSQL queries bypassing row-level security policies","sev":"critical","tags":["database","postgresql","rls-bypass","sql"],"mitre":["T1078"],"compliance":["PCI-DSS-8.5","GDPR-25-003"],"qh":"DISABLE ROW LEVEL SECURITY|SET ROLE|SECURITY DEFINER|RLS bypass"},
    {"id":"DB-MY-001","name":"MySQL — UNION-Based SQL Injection","desc":"Detects UNION-based SQL injection attacks against MySQL databases","sev":"critical","tags":["database","mysql","sql-injection","sql"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"UNION SELECT|information_schema|mysql.user|SQL injection"},
    {"id":"DB-MY-002","name":"MySQL — Root Account Remote Login","desc":"Detects remote login attempts to MySQL root account from non-localhost","sev":"critical","tags":["database","mysql","default-account","sql"],"mitre":["T1078.001"],"compliance":["PCI-DSS-2.1"],"qh":"root@%|root login|remote root|mysql root"},
    {"id":"DB-MSS-001","name":"SQL Server — xp_cmdshell Execution","desc":"Detects execution of xp_cmdshell stored procedure enabling OS command execution","sev":"critical","tags":["database","sqlserver","command-execution","sql"],"mitre":["T1059"],"compliance":["PCI-DSS-6.5"],"qh":"xp_cmdshell|sp_OACreate|sp_configure|cmdshell"},
    {"id":"DB-MSS-002","name":"SQL Server — SUSPENDED Login State Anomaly","desc":"Detects SQL Server logins in SUSPENDED state indicating potential credential abuse","sev":"medium","tags":["database","sqlserver","login-anomaly","sql"],"mitre":["T1078"],"compliance":["PCI-DSS-8.5"],"qh":"SUSPENDED login|login denied|disabled account|SQL Server auth"},
    {"id":"DB-ORA-001","name":"Oracle — DBA Privilege Escalation","desc":"Detects Oracle DBA privilege escalation attempts via GRANT DBA or ALTER USER","sev":"critical","tags":["database","oracle","privilege-escalation","sql"],"mitre":["T1548"],"compliance":["PCI-DSS-8.5"],"qh":"GRANT DBA|ALTER USER|SYSDBA|privilege escalation"},
    {"id":"DB-SQLITE-001","name":"SQLite — Direct File Access from Web","desc":"Detects direct SQLite database file access from web applications","sev":"high","tags":["database","sqlite","file-access","sql"],"mitre":["T1083"],"compliance":["PCI-DSS-6.5"],"qh":".db download|sqlite file|path traversal|database file access"},
    # NoSQL
    {"id":"DB-MONGO-001","name":"MongoDB — NoSQL Injection via $where","desc":"Detects MongoDB $where operator injection for JavaScript execution","sev":"critical","tags":["database","mongodb","nosql-injection","nosql"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"$where|$regex|{$gt:|NoSQL injection|admin.system.users"},
    {"id":"DB-MONGO-002","name":"MongoDB — admin Database Unauthorized Access","desc":"Detects unauthorized access to MongoDB admin database","sev":"critical","tags":["database","mongodb","default-account","nosql"],"mitre":["T1078.001"],"compliance":["PCI-DSS-2.1"],"qh":"admin.system.users|mongo admin|unauthorized access"},
    {"id":"DB-DYNAMO-001","name":"DynamoDB — Excessive Scan Operations","desc":"Detects excessive DynamoDB Scan operations indicating potential data exfiltration","sev":"high","tags":["database","dynamodb","data-exfiltration","nosql"],"mitre":["T1213"],"compliance":["GDPR-25-008"],"qh":"DynamoDB Scan|excessive read|data exfiltration|ScanConsumedCapacity"},
    {"id":"DB-CASS-001","name":"Cassandra — Unauthorized CQL Command Execution","desc":"Detects unauthorized CQL commands including ALTER, DROP, and GRANT operations","sev":"critical","tags":["database","cassandra","privilege-escalation","nosql"],"mitre":["T1548"],"compliance":["PCI-DSS-8.5"],"qh":"ALTER KEYSPACE|DROP TABLE|GRANT ALL|Cassandra unauthorized"},
    {"id":"DB-COUCH-001","name":"CouchDB — Admin Party Mode","desc":"Detects CouchDB admin party mode or unauthorized admin access","sev":"critical","tags":["database","couchdb","default-account","nosql"],"mitre":["T1078.001"],"compliance":["PCI-DSS-2.1"],"qh":"admin party|_users|CouchDB unauthorized|no authentication"},
    {"id":"DB-FIRE-001","name":"Firestore — Overly Permissive Security Rules","desc":"Detects Firestore security rules allowing unauthenticated read/write access","sev":"high","tags":["database","firestore","misconfiguration","nosql"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"allow read, write|allow all|if true|Firestore permissive"},
    # Graph Databases
    {"id":"DB-NEO4J-001","name":"Neo4j — Cypher Injection Attack","desc":"Detects Cypher injection attacks in Neo4j graph database queries","sev":"critical","tags":["database","neo4j","cypher-injection","graph"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"Cypher injection|MATCH (n)|DETACH DELETE|neo4j unauthorized"},
    {"id":"DB-ARANGO-001","name":"ArangoDB — AQL Injection Detection","desc":"Detects AQL injection attacks in ArangoDB queries","sev":"high","tags":["database","arangodb","aql-injection","graph"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"AQL injection|FOR x IN|ArangoDB injection|query manipulation"},
    {"id":"DB-NEPTUNE-001","name":"Neptune — Gremlin/SPARQL Injection","desc":"Detects Gremlin or SPARQL injection attacks against Amazon Neptune","sev":"high","tags":["database","neptune","graph-injection","graph"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"Gremlin injection|SPARQL injection|Neptune unauthorized|query manipulation"},
    # Time-Series
    {"id":"DB-INFLUX-001","name":"InfluxDB — Unauthorized Data Deletion","desc":"Detects DROP DATABASE or DELETE SERIES commands in InfluxDB","sev":"critical","tags":["database","influxdb","data-destruction","timeseries"],"mitre":["T1485"],"compliance":["PCI-DSS-3.4"],"qh":"DROP DATABASE|DELETE SERIES|InfluxDB drop|data destruction"},
    {"id":"DB-TSCALE-001","name":"TimescaleDB — Hypertable Data Exfiltration","desc":"Detects bulk data extraction from TimescaleDB hypertables","sev":"high","tags":["database","timescaledb","data-exfiltration","timeseries"],"mitre":["T1213"],"compliance":["GDPR-25-008"],"qh":"COPY TO|bulk export|hypertable scan|data exfiltration"},
    {"id":"DB-PROM-001","name":"Prometheus — Unauthorized Metric Scraping","desc":"Detects unauthorized metric scraping from Prometheus endpoints revealing infrastructure details","sev":"medium","tags":["database","prometheus","information-disclosure","timeseries"],"mitre":["T1592"],"compliance":["NIST-CM-7"],"qh":"/metrics|prometheus scrape|unauthorized metric|infrastructure disclosure"},
    # Vector Databases
    {"id":"DB-PINE-001","name":"Pinecone — Namespace Isolation Bypass","desc":"Detects cross-namespace data access in Pinecone vector database","sev":"critical","tags":["database","pinecone","vector","isolation-bypass"],"mitre":["T1078"],"compliance":["GDPR-25-003"],"qh":"pinecone namespace bypass|cross-namespace query|isolation failure"},
    {"id":"DB-WEAV-001","name":"Weaviate — Tenant Data Isolation Failure","desc":"Detects cross-tenant data access in Weaviate vector database","sev":"critical","tags":["database","weaviate","vector","isolation-bypass"],"mitre":["T1078"],"compliance":["GDPR-25-003"],"qh":"weaviate tenant bypass|cross-tenant query|isolation failure"},
    {"id":"DB-MILV-001","name":"Milvus — Collection-Level Access Bypass","desc":"Detects unauthorized collection access in Milvus vector database","sev":"high","tags":["database","milvus","vector","access-bypass"],"mitre":["T1078"],"compliance":["PCI-DSS-8.5"],"qh":"milvus unauthorized|collection bypass|vector access violation"},
    {"id":"DB-CHROMA-001","name":"ChromaDB — Embedding Poisoning Detection","desc":"Detects adversarial embedding vectors inserted into ChromaDB collections","sev":"high","tags":["database","chromadb","vector","embedding-poisoning"],"mitre":["T1190"],"compliance":["AI-ACT-15"],"qh":"chromadb poisoning|adversarial embedding|vector manipulation"},
    {"id":"DB-QDRANT-001","name":"Qdrant — Payload Filter Injection","desc":"Detects filter injection attacks in Qdrant vector search payloads","sev":"high","tags":["database","qdrant","vector","filter-injection"],"mitre":["T1190"],"compliance":["PCI-DSS-6.5"],"qh":"qdrant filter injection|payload manipulation|vector search abuse"},
    # Key-Value Stores
    {"id":"DB-REDIS-001","name":"Redis — CONFIG GET Credential Exposure","desc":"Detects Redis CONFIG commands targeting credentials or authentication configuration","sev":"critical","tags":["database","redis","credential-exposure","key-value"],"mitre":["T1552"],"compliance":["PCI-DSS-3.4"],"qh":"CONFIG GET|ACL LIST|requirepass|Redis credential"},
    {"id":"DB-REDIS-002","name":"Redis — FLUSHALL/FLUSHDB Data Destruction","desc":"Detects Redis FLUSHALL or FLUSHDB commands indicating potential data destruction","sev":"critical","tags":["database","redis","data-destruction","key-value"],"mitre":["T1485"],"compliance":["PCI-DSS-3.4"],"qh":"FLUSHALL|FLUSHDB|data destruction|Redis wipe"},
    {"id":"DB-MEMC-001","name":"Memcached — Amplification Attack","desc":"Detects Memcached amplification attacks via stats or get requests from external IPs","sev":"high","tags":["database","memcached","amplification","key-value"],"mitre":["T1498"],"compliance":["NIST-SC-5"],"qh":"stats|amplification|memcached DDoS|UDP reflection"},
    # Column-Family
    {"id":"DB-HBASE-001","name":"HBase — Unauthorized ACL Modification","desc":"Detects unauthorized ACL modifications in HBase including grant and revoke operations","sev":"critical","tags":["database","hbase","acl-modification","column-family"],"mitre":["T1548"],"compliance":["PCI-DSS-8.5"],"qh":"grant|revoke|HBase ACL|unauthorized permission"},
]

# ============================================================
# PLATFORM FORMATTERS
# ============================================================

def fmt_elastic(rules, cat_name):
    out = []
    for r in rules:
        sev = r["sev"]
        tags = r["tags"]
        qh = r["qh"]
        tag_filter = ' OR '.join(['"' + t + '"' for t in tags[1:4]])
        query_str = 'event.category:("network" OR "authentication" OR "database" OR "iam") AND (' + tag_filter + ')'
        out.append({
            "rule_id": f"ES-{r['id']}",
            "name": r["name"],
            "description": r["desc"],
            "severity": sev,
            "type": "query",
            "query": query_str,
            "index": ["logs-*"],
            "references": [r["id"]],
            "mitre": r["mitre"],
            "compliance": r["compliance"],
            "tags": tags,
            "risk_score": SEV_NUM.get(sev, 5) * 10,
            "interval": "5m"
        })
    return {"description": f"Elastic Security SIEM alert rules — {cat_name}", "version": "1.0.0", "elastic_version": "8.x", "total_rules": len(out), "rules": out}

def fmt_splunk(rules, cat_name):
    lines = [f"# =============================================================================",
             f"# Splunk SIEM Alert Rules — {cat_name}",
             f"# =============================================================================\n"]
    for r in rules:
        pid = f"SPL-{r['id']}"
        tags = r["tags"]
        search_terms = " OR ".join([f'"{t}"' for t in tags[1:4]])
        action = "email" if r["sev"] in ["critical","high"] else "log"
        lines.append(f"[{pid}]")
        lines.append(f"name = {r['name']}")
        lines.append(f"description = {r['desc']}")
        lines.append(f"severity = {r['sev']}")
        lines.append(f"search = index=* ({search_terms}) | stats count, values(src_ip) as src_ips, values(dest_ip) as dest_ips by rule_id, rule_name | where count > 5")
        lines.append(f"sourcetype = access_logs,auth_logs,firewall")
        lines.append(f"action = {action}")
        lines.append(f"references = {r['id']}")
        lines.append(f"mitre = {','.join(r['mitre']) if r['mitre'] else 'N/A'}")
        lines.append(f"compliance = {','.join(r['compliance'])}")
        lines.append(f"risk_score = {SEV_NUM.get(r['sev'],5)*10}\n")
    return "\n".join(lines)

def fmt_qradar(rules, cat_name):
    out = []
    for r in rules:
        tags = r["tags"]
        conditions = " OR ".join([f"payload ILIKE '%{t}%'" for t in tags[1:3]])
        tactic = "Initial Access" if "T1190" in r["mitre"] else "Credential Access" if "T1110" in r["mitre"] else "Discovery" if "T1087" in r["mitre"] or "T1592" in r["mitre"] else "Defense Evasion" if "T1562" in r["mitre"] or "T1548" in r["mitre"] else "Lateral Movement" if any("T1021" in m or "T1550" in m for m in r["mitre"]) else "Execution" if "T1059" in r["mitre"] else "Persistence" if "T1053" in r["mitre"] else "Impact" if "T1486" in r["mitre"] else "Exfiltration" if "T1048" in r["mitre"] else "Collection"
        out.append({
            "rule_id": f"QR-{r['id']}",
            "name": r["name"],
            "description": r["desc"],
            "severity": SEV_NUM.get(r["sev"], 5),
            "aql_query": f"SELECT sourceip, destinationip, URL, payload FROM events WHERE ({conditions}) GROUP BY sourceip, destinationip, URL LAST 15 MINUTES",
            "log_source": "APPLICATION_LOG",
            "references": [r["id"]],
            "mitre": {"tactic": tactic, "technique": r["mitre"][0] if r["mitre"] else "N/A"},
            "compliance": r["compliance"],
            "credibility": 7,
            "relevance": SEV_NUM.get(r["sev"], 5)
        })
    return {"version": "1.0.0", "generated": "2026-08-17", "description": f"QRadar SIEM alert rules — {cat_name}", "total_rules": len(out), "rules": out}

def fmt_wazuh(rules, cat_name):
    lines = [f'<!--\n  Wazuh SIEM Alert Rules — {cat_name}\n  Total rules: {len(rules)}\n-->\n<group name="wazuh,{cat_name.replace("-",",")}">\n']
    for r in rules:
        level = SEV_NUM.get(r["sev"], 5)
        group_str = ",".join(r["tags"][:3])
        match_text = "|".join(r["tags"][1:3])
        mitre_ids = " ".join(r["mitre"]) if r["mitre"] else ""
        compliance_parts = []
        for c in r["compliance"]:
            if "PCI" in c: compliance_parts.append(f'<pci_dss>{c.split("-")[-1]}</pci_dss>')
            elif "GDPR" in c: compliance_parts.append(f'<gdpr>{c}</gdpr>')
            elif "HIPAA" in c: compliance_parts.append(f'<hipaa>{c}</hipaa>')
            elif "NIST" in c: compliance_parts.append(f'<nist_800_53>{c.replace("NIST-","")}</nist_800_53>')
        compliance_str = "\n      ".join(compliance_parts) if compliance_parts else ""
        rid = r["id"].replace("-","")
        lines.append(f'  <rule id="WZ-{rid}" level="{level}" group="{group_str}">')
        lines.append(f'    <description>{r["name"]} — {r["desc"][:80]}</description>')
        lines.append(f'    <decoded_as>web_log</decoded_as>')
        lines.append(f'    <field name="test_id">{r["id"]}</field>')
        lines.append(f'    <mitre>')
        lines.append(f'      <id>{mitre_ids}</id>')
        lines.append(f'    </mitre>')
        if compliance_str:
            lines.append(f'    <compliance>')
            lines.append(f'      {compliance_str}')
            lines.append(f'    </compliance>')
        lines.append(f'    <match>{match_text}</match>')
        lines.append(f'  </rule>\n')
    lines.append("</group>")
    return "\n".join(lines)

def fmt_fortisiem(rules, cat_name):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', f'<!-- FortiSIEM Pattern Rules — {cat_name} -->', f'<!-- Total rules: {len(rules)} -->', '<Rules>']
    for r in rules:
        rid = f"FSIEM-{r['id']}"
        etype = r["tags"][1].replace("-","_").upper() if len(r["tags"])>1 else "GENERIC"
        patterns = " OR ".join([f'"{t}"' for t in r["tags"][1:3]])
        lines.append(f'  <Rule name="{rid}" id="{rid}">')
        lines.append(f'    <Description>{r["desc"]}</Description>')
        lines.append(f'    <Severity>{SEV_FORT.get(r["sev"],"Medium")}</Severity>')
        lines.append(f'    <Pattern>{patterns}</Pattern>')
        lines.append(f'    <EventType>{etype}</EventType>')
        lines.append(f'    <MITRE>{",".join(r["mitre"]) if r["mitre"] else "N/A"}</MITRE>')
        lines.append(f'    <Compliance>{",".join(r["compliance"])}</Compliance>')
        lines.append(f'  </Rule>')
    lines.append('</Rules>')
    return "\n".join(lines)

def fmt_sentinel(rules, cat_name):
    out = []
    for r in rules:
        tags_str = ", ".join([f'"{t}"' for t in r["tags"][:4]])
        cat_tag = r["tags"][1].replace("-","_") if len(r["tags"])>1 else "generic"
        kql = f'let threshold = 5;\n{cat_tag}_events\n| where {cat_tag} has_any({tags_str})\n| summarize count() by SourceIP, bin(TimeGenerated, 5m)\n| where count_ > threshold'
        tactics = []
        tactic_map = {"T1190":"InitialAccess","T1592":"Discovery","T1110":"CredentialAccess","T1078":"DefenseEvasion","T1548":"PrivilegeEscalation","T1562":"DefenseEvasion","T1486":"Impact","T1566":"InitialAccess","T1053":"Persistence","T1071":"CommandAndControl","T1059":"Execution","T1087":"Discovery","T1210":"LateralMovement","T1055":"DefenseEvasion","T1003":"CredentialAccess","T1046":"Discovery","T1048":"Exfiltration","T1550.002":"LateralMovement","T1550.003":"LateralMovement","T1021.001":"LateralMovement","T1021.004":"LateralMovement","T1047":"Execution","T1021.002":"LateralMovement","T1021.003":"LateralMovement","T1021.006":"LateralMovement","T1558.001":"CredentialAccess","T1558.002":"CredentialAccess","T1189":"InitialAccess","T1539":"Discovery","T1187":"Discovery","T1606":"CredentialAccess","T1534":"CredentialAccess","T1078.001":"DefenseEvasion","T1110.001":"CredentialAccess","T1110.003":"CredentialAccess","T1110.004":"CredentialAccess","T1111":"CredentialAccess","T1498":"Impact","T1499":"Impact","T1129":"Execution","T1105":"CommandAndControl","T1213":"Collection","T1592.001":"Discovery","T1552":"CredentialAccess","T1552.001":"CredentialAccess","T1552.007":"CredentialAccess","T1557":"ManInTheMiddle","T1113":"Collection","T1136":"Persistence","T1528":"CredentialAccess","T1573":"CommandAndControl","T1584.001":"InitialAccess","T1580":"Discovery","T1537":"Exfiltration","T1083":"Discovery","T1485":"Impact","T1116":"DefenseEvasion"}
        for m in r["mitre"]:
            if m in tactic_map and tactic_map[m] not in tactics:
                tactics.append(tactic_map[m])
        out.append({
            "rule_id": f"MS-{r['id']}",
            "name": r["name"],
            "description": r["desc"],
            "severity": SEV_SENT.get(r["sev"], "Medium"),
            "query": kql,
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 5,
            "tactics": tactics if tactics else ["InitialAccess"],
            "techniques": r["mitre"],
            "references": [r["id"]],
            "compliance": r["compliance"],
            "tags": r["tags"],
            "risk_score": SEV_NUM.get(r["sev"], 5) * 10
        })
    return {"version": "1.0.0", "generated": "2026-08-17", "description": f"Microsoft Sentinel analytics rules — {cat_name}", "total_rules": len(out), "rules": out}

def fmt_zeek(rules, cat_name):
    lines = [f"# =============================================================================",
             f"# Zeek Signatures — {cat_name}",
             f"# Total rules: {len(rules)}",
             f"# =============================================================================\n"]
    for r in rules:
        sid = f"ZK-{r['id'].replace('-','')}"
        match_re = "|".join(r["tags"][1:3])
        lines.append(f"signature {sid} {{")
        lines.append(f"\tip-proto tcp")
        lines.append(f"\tsrc-ip $HOME_NET")
        lines.append(f"\tdst-port 80 443 8080 8443")
        lines.append(f"\tpayload /{match_re}/")
        lines.append(f'\tevent "Detect_{r["name"].replace(" ","_")[:40]}"')
        lines.append(f"}}\n")
    return "\n".join(lines)

def fmt_suricata(rules, cat_name):
    lines = [f"# =============================================================================",
             f"# Suricata Rules — {cat_name}",
             f"# Total rules: {len(rules)}",
             f"# =============================================================================\n"]
    for i, r in enumerate(rules):
        rid = f"SUR-{r['id']}"
        sev_n = {"critical":1,"high":2,"medium":3,"low":4,"informational":4}
        content_parts = " ".join([f'content:"{t}";' for t in r["tags"][1:3]])
        sid = 3000000 + i
        lines.append(f'{rid} http any any -> $HOME_NET any (msg:"SIEM {r["name"][:80]}"; {content_parts} classtype:attempted-admin; sid:{sid}; rev:1; severity:{sev_n.get(r["sev"],3)}; metadata:mitre {",".join(r["mitre"])};)')
    return "\n".join(lines)

def fmt_oci(rules, cat_name):
    out = []
    for r in rules:
        out.append({
            "rule_id": f"OCI-{r['id']}",
            "name": r["name"],
            "description": r["desc"],
            "severity": SEV_OCI.get(r["sev"], "MEDIUM"),
            "condition": {"eventType": ["com.oracle.cloud.monitoring"], "compartmentId": "$COMPARTMENT_ID", "metric": r["tags"][1].replace("-","_"), "operator": "GT", "threshold": 5},
            "actions": [{"actionType": "ONS", "description": "Send alert notification"}],
            "references": r["compliance"],
            "mitre": r["mitre"],
            "tags": r["tags"]
        })
    return {"version": "1.0.0", "generated": "2026-08-17", "description": f"OCI Alarm and Event rules — {cat_name}", "total_rules": len(out), "rules": out}

def fmt_azure(rules, cat_name):
    out = []
    for r in rules:
        cat_tag = r["tags"][1].replace("-","_") if len(r["tags"])>1 else "generic"
        out.append({
            "rule_id": f"AZ-{r['id']}",
            "name": r["name"],
            "description": r["desc"],
            "severity": SEV_AZURE.get(r["sev"], 2),
            "query": f"AzureDiagnostics | where Category contains '{cat_tag}' | summarize count() by bin(TimeGenerated, 5m), resource_group | where count_ > 5",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 5,
            "tactics": r["mitre"],
            "compliance": r["compliance"],
            "tags": r["tags"],
            "risk_score": SEV_NUM.get(r["sev"], 5) * 10
        })
    return {"version": "1.0.0", "generated": "2026-08-17", "description": f"Azure Monitor and Policy rules — {cat_name}", "total_rules": len(out), "rules": out}

def fmt_aws(rules, cat_name):
    out = []
    for r in rules:
        cat_tag = r["tags"][1].replace("-","_") if len(r["tags"])>1 else "generic"
        out.append({
            "rule_id": f"AWS-{r['id']}",
            "name": r["name"],
            "description": r["desc"],
            "severity": r["sev"],
            "cloudwatch_metric": {"namespace": "SIEM/Security", "metricName": cat_tag, "dimensions": {"RuleId": f"AWS-{r['id']}"}, "statistic": "Sum", "period": 300, "evaluationPeriods": 1, "threshold": 5, "comparisonOperator": "GreaterThanThreshold"},
            "eventbridge_pattern": {"source": ["aws.security", "aws.guardduty", "aws.cloudtrail"], "detail-type": ["AWS API Call via CloudTrail", "GuardDuty Finding"], "detail": {"eventSource": ["cloudtrail.amazonaws.com"], "eventName": [cat_tag]}},
            "guardduty_finding": {"severity": SEV_NUM.get(r["sev"], 5), "type": cat_tag.upper()},
            "references": r["compliance"],
            "mitre": r["mitre"],
            "tags": r["tags"],
            "risk_score": SEV_NUM.get(r["sev"], 5) * 10
        })
    return {"version": "1.0.0", "generated": "2026-08-17", "description": f"AWS CloudWatch, EventBridge, and GuardDuty rules — {cat_name}", "total_rules": len(out), "rules": out}

FORMATTERS = {
    "elastic": ("json", fmt_elastic),
    "splunk": ("conf", fmt_splunk),
    "qradar": ("json", fmt_qradar),
    "wazuh": ("xml", fmt_wazuh),
    "fortisiem": ("xml", fmt_fortisiem),
    "sentinel": ("json", fmt_sentinel),
    "zeek": ("zeek", fmt_zeek),
    "suricata": ("rules", fmt_suricata),
    "oracle": ("json", fmt_oci),
    "azure": ("json", fmt_azure),
    "aws": ("json", fmt_aws),
}

# ============================================================
# GENERATE ALL FILES
# ============================================================

total_rules = 0
total_files = 0

for platform, (ext, formatter) in FORMATTERS.items():
    platform_dir = os.path.join(RULES, platform)
    platform_total = 0

    for cat_name, rules in ALL_RULES.items():
        filename = f"{cat_name}.{ext}"
        filepath = os.path.join(platform_dir, filename)

        # Skip if existing file has more content (for elastic/wazuh/qradar/splunk)
        if platform in ["elastic","qradar","wazuh","splunk"] and cat_name in ["wstg-01-03","wstg-04-06"]:
            if os.path.exists(filepath) and os.path.getsize(filepath) > 1000:
                print(f"  Skipping {platform}/{filename} (existing file is substantial)")
                # Count existing rules
                try:
                    if ext == "json":
                        with open(filepath) as f:
                            d = json.load(f)
                            platform_total += d.get("total_rules", 0)
                    elif ext in ["conf", "xml", "zeek", "rules"]:
                        with open(filepath) as f:
                            content = f.read()
                            # Count rule stanzas
                            if ext == "conf":
                                platform_total += content.count("\n[")
                            elif ext == "xml":
                                platform_total += content.count('<rule id=')
                except:
                    pass
                continue

        result = formatter(rules, cat_name)
        if ext == "json":
            with open(filepath, "w") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            platform_total += len(rules)
        else:
            with open(filepath, "w") as f:
                f.write(result)
            platform_total += len(rules)
        total_files += 1

    total_rules += platform_total
    print(f"  {platform}: {platform_total} rules across {len(ALL_RULES)} categories")

print(f"\nGenerated {total_rules} rules across all platforms")

# ============================================================
# GENERATE MAPPING FILES
# ============================================================

print("\nGenerating mapping files...")

# Collect all rule IDs
all_rule_ids = {}
for cat_name, rules in ALL_RULES.items():
    for r in rules:
        all_rule_ids[r["id"]] = {"category": cat_name, "name": r["name"], "severity": r["sev"], "mitre": r["mitre"], "compliance": r["compliance"], "tags": r["tags"]}

# test-to-siem.json
test_to_siem = []
for rid, data in all_rule_ids.items():
    test_to_siem.append({
        "test_id": rid,
        "test_name": data["name"],
        "siem_rules": {p: f"{p_prefix}-{rid}" for p, p_prefix in [("elastic","ES"),("splunk","SPL"),("qradar","QR"),("wazuh","WZ"),("fortisiem","FSIEM"),("sentinel","MS"),("zeek","ZK"),("suricata","SUR"),("oracle","OCI"),("azure","AZ"),("aws","AWS")]},
        "category": data["category"],
        "severity": data["severity"]
    })
with open(os.path.join(MAPPINGS, "test-to-siem.json"), "w") as f:
    json.dump({"version": "1.0.0", "total_mappings": len(test_to_siem), "mappings": test_to_siem}, f, indent=2, ensure_ascii=False)
print(f"  test-to-siem.json: {len(test_to_siem)} mappings")

# mitre-to-siem.json
mitre_map = {}
for rid, data in all_rule_ids.items():
    for m in data["mitre"]:
        if m not in mitre_map:
            mitre_map[m] = []
        mitre_map[m].append({"rule_id": rid, "name": data["name"], "category": data["category"], "severity": data["severity"]})
with open(os.path.join(MAPPINGS, "mitre-to-siem.json"), "w") as f:
    json.dump({"version": "1.0.0", "total_techniques": len(mitre_map), "mappings": mitre_map}, f, indent=2, ensure_ascii=False)
print(f"  mitre-to-siem.json: {len(mitre_map)} techniques")

# regulatory-cross-map.json
regulatory_map = {}
frameworks = ["PCI-DSS", "GDPR", "HIPAA", "NIST", "NIS2", "DORA", "Data-Act", "AI-Act"]
for fw in frameworks:
    fw_rules = []
    for rid, data in all_rule_ids.items():
        for c in data["compliance"]:
            if fw.upper() in c.upper() or (fw == "Data-Act" and "DATA" in c.upper()) or (fw == "AI-Act" and ("AI-ACT" in c.upper() or "AI-" in c.upper())):
                fw_rules.append({"rule_id": rid, "name": data["name"], "compliance_ref": c, "severity": data["severity"]})
                break
    regulatory_map[fw] = fw_rules
with open(os.path.join(MAPPINGS, "regulatory-cross-map.json"), "w") as f:
    json.dump({"version": "1.0.0", "frameworks": {k: len(v) for k,v in regulatory_map.items()}, "mappings": regulatory_map}, f, indent=2, ensure_ascii=False)
print(f"  regulatory-cross-map.json: {len(regulatory_map)} frameworks")

# Individual compliance mappings
compliance_files = {
    "pci-dss-mappings.json": "PCI-DSS",
    "gdpr-mappings.json": "GDPR",
    "hipaa-mappings.json": "HIPAA",
    "nist-mappings.json": "NIST",
    "nis2-mappings.json": "NIS2",
    "dora-mappings.json": "DORA",
    "data-act-mappings.json": "Data-Act",
    "ai-act-mappings.json": "AI-Act",
}
for fname, fw in compliance_files.items():
    fw_rules = []
    for rid, data in all_rule_ids.items():
        matched = []
        for c in data["compliance"]:
            if fw.upper() in c.upper() or (fw == "Data-Act" and "DATA" in c.upper()) or (fw == "AI-Act" and ("AI-ACT" in c.upper() or "AI-" in c.upper())):
                matched.append(c)
        if matched:
            fw_rules.append({"rule_id": rid, "name": data["name"], "severity": data["severity"], "compliance_refs": matched, "mitre": data["mitre"]})
    with open(os.path.join(MAPPINGS, fname), "w") as f:
        json.dump({"version": "1.0.0", "framework": fw, "total_rules": len(fw_rules), "mappings": fw_rules}, f, indent=2, ensure_ascii=False)
    print(f"  {fname}: {len(fw_rules)} rules")

# database-to-siem.json
db_map_fixed = {}
for rid_key, data in all_rule_ids.items():
    if "database" in data["tags"] or any(t in data["tags"] for t in ["sql","nosql","vector","graph","timeseries","key-value","column-family"]):
        db_type = "other"
        for tag in data["tags"]:
            db_types = ["postgresql","mysql","sqlserver","oracle","sqlite","mongodb","dynamodb","cassandra","couchdb","firestore","neo4j","arangodb","neptune","influxdb","timescaledb","prometheus","pinecone","weaviate","milvus","chromadb","qdrant","redis","memcached","hbase"]
            if tag in db_types:
                db_type = tag
                break
        if db_type not in db_map_fixed:
            db_map_fixed[db_type] = []
        db_map_fixed[db_type].append({"rule_id": rid_key, "name": data["name"], "severity": data["severity"]})

with open(os.path.join(MAPPINGS, "database-to-siem.json"), "w") as f:
    json.dump({"version": "1.0.0", "total_databases": len(db_map_fixed), "total_rules": sum(len(v) for v in db_map_fixed.values()), "mappings": db_map_fixed}, f, indent=2, ensure_ascii=False)
print(f"  database-to-siem.json: {len(db_map_fixed)} databases, {sum(len(v) for v in db_map_fixed.values())} rules")

# Platform-specific mappings
for platform, prefix in [("elastic","ES"),("splunk","SPL"),("qradar","QR"),("wazuh","WZ"),("fortisiem","FSIEM"),("sentinel","MS"),("zeek","ZK"),("suricata","SUR"),("oracle","OCI"),("azure","AZ"),("aws","AWS")]:
    plat_map = []
    for rid, data in all_rule_ids.items():
        plat_map.append({"rule_id": f"{prefix}-{rid}", "test_id": rid, "name": data["name"], "category": data["category"], "severity": data["severity"], "mitre": data["mitre"]})
    with open(os.path.join(MAPPINGS, f"{platform}-mappings.json"), "w") as f:
        json.dump({"version": "1.0.0", "platform": platform, "total_rules": len(plat_map), "mappings": plat_map}, f, indent=2, ensure_ascii=False)
    print(f"  {platform}-mappings.json: {len(plat_map)} rules")

print(f"\nTotal mapping files generated!")
print(f"\nNow generating docs and scripts...")