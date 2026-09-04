#!/usr/bin/env python3
"""
Threat Intel Ingestion Module
Pulls live threat intelligence from:
  - CISA KEV (Known Exploited Vulnerabilities)
  - NVD CVE (recent high/critical CVEs)
  - MITRE ATT&CK (techniques and sub-techniques)
  - AlienVault OTX (pulse indicators) — optional, API key preferred
Outputs normalized threat intel JSON for rule generation.
"""

import json, os, sys, time, hashlib, re
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: requests module required. pip3 install requests")
    sys.exit(1)

BASE = Path(__file__).parent
CACHE_DIR = BASE / "cache"
OUTPUT_DIR = BASE / "threat_intel"
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── CISA KEV ────────────────────────────────────────────────

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    cache = CACHE_DIR / "cisa_kev.json"
    if cache.exists() and (time.time() - cache.stat().st_mtime) < 86400:
        data = json.loads(cache.read_text())
    else:
        r = requests.get(CISA_KEV_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
        cache.write_text(json.dumps(data, indent=2))

    vulns = []
    for v in data.get("vulnerabilities", []):
        cve_id = v.get("cveID", "")
        product = v.get("product", "")
        vendor = v.get("vendorProject", "")
        vuln_date = v.get("dateAdded", "")
        desc = v.get("shortDescription", "")
        due_date = v.get("dueDate", "")
        known_ransomware = v.get("knownRansomwareCampaignUse", "Unknown")

        vulns.append({
            "source": "cisa_kev",
            "cve_id": cve_id,
            "product": product,
            "vendor": vendor,
            "date_added": vuln_date,
            "due_date": due_date,
            "description": desc,
            "known_ransomware_use": known_ransomware,
            "severity": "critical",  # KEV = exploited = critical
            "category": _categorize_product(product, desc),
            "mitre_techniques": _map_to_mitre(desc, product),
        })

    print(f"  CISA KEV: {len(vulns)} vulnerabilities")
    return vulns


def _categorize_product(product, desc):
    """Map product/description to SIEM category."""
    p = product.lower()
    d = desc.lower()
    if any(x in p for x in ["windows", "microsoft", "active directory", "exchange", "iis"]):
        return "endpoint"
    if any(x in p for x in ["apache", "nginx", "tomcat", "wordpress", "drupal", "joomla", "struts"]):
        return "web-application"
    if any(x in p for x in ["cisco", "fortinet", "paloalto", "juniper", "vpn", "firewall"]):
        return "network-infrastructure"
    if any(x in p for x in ["oracle", "mysql", "postgresql", "mongodb", "redis", "mssql", "sql server"]):
        return "database"
    if any(x in p for x in ["kubernetes", "docker", "container", "vmware", "esxi"]):
        return "cloud-container"
    if any(x in p for x in ["android", "ios", "mobile"]):
        return "mobile"
    if any(x in p for x in ["chrome", "firefox", "safari", "browser"]):
        return "client-application"
    if any(x in p for x in ["openssl", "log4j", "log4shell", "spring", "openssl"]):
        return "supply-chain"
    if any(x in p for x in ["atlassian", "confluence", "jira", "gitlab", "github"]):
        return "devops-collaboration"
    if any(x in d for x in ["rce", "remote code exec", "arbitrary code"]):
        return "remote-code-execution"
    if any(x in d for x in ["privilege escalat", "elevation of privilege"]):
        return "privilege-escalation"
    if any(x in d for x in ["sql injection", "sqli"]):
        return "sql-injection"
    if any(x in d for x in ["xss", "cross-site scripting"]):
        return "xss"
    if any(x in d for x in ["ssrf", "server-side request"]):
        return "ssrf"
    return "general"


def _map_to_mitre(desc, product):
    """Map vulnerability description to MITRE ATT&CK techniques."""
    d = desc.lower()
    techniques = []
    if any(x in d for x in ["rce", "remote code exec", "arbitrary code"]):
        techniques.extend(["T1190", "T1059"])
    if any(x in d for x in ["privilege escalat", "elevation"]):
        techniques.append("T1548")
    if any(x in d for x in ["sql injection", "sqli"]):
        techniques.append("T1190")
    if any(x in d for x in ["xss", "cross-site scripting"]):
        techniques.append("T1059.007")
    if any(x in d for x in ["ssrf", "server-side request"]):
        techniques.append("T1190")
    if any(x in d for x in ["credential", "password", "auth"]):
        techniques.extend(["T1078", "T1110"])
    if any(x in d for x in ["bypass", "circumvent"]):
        techniques.append("T1548")
    if any(x in d for x in ["denial of service", "dos"]):
        techniques.append("T1498")
    if any(x in d for x in ["information disclos", "data leak", "sensitive"]):
        techniques.extend(["T1592", "T1213"])
    if any(x in d for x in ["phishing"]):
        techniques.append("T1566")
    if any(x in d for x in ["supply chain", "dependency"]):
        techniques.append("T1195")
    if any(x in d for x in ["lateral movement", "pivot"]):
        techniques.append("T1021")
    if "vpn" in product.lower() or "vpn" in d:
        techniques.extend(["T1133", "T1190"])
    return list(set(techniques))


# ─── NVD CVE ─────────────────────────────────────────────────

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_recent(days=7, severity="HIGH"):
    """Fetch recent high/critical CVEs from NVD."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
    params = {
        "pubStartDate": since,
        "cvssV3Severity": severity,
    }
    
    cache = CACHE_DIR / f"nvd_{severity.lower()}_{days}d.json"
    if cache.exists() and (time.time() - cache.stat().st_mtime) < 86400:
        data = json.loads(cache.read_text())
    else:
        r = requests.get(NVD_API, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
        cache.write_text(json.dumps(data, indent=2))

    vulns = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = [d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"]
        desc = descriptions[0] if descriptions else ""
        
        # Extract CVSS
        metrics = cve.get("metrics", {})
        cvss3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
        cvss3 = metrics.get("cvssMetricV30", [{}])[0] if not cvss3 and metrics.get("cvssMetricV30") else cvss3
        score = cvss3.get("cvssData", {}).get("baseScore", 0)
        severity_level = "critical" if score >= 9.0 else "high" if score >= 7.0 else "medium"

        # Extract affected products (CPE)
        cpes = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpes.append(cpe_match.get("criteria", ""))

        vulns.append({
            "source": "nvd",
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": score,
            "severity": severity_level,
            "cpes": cpes[:10],  # Limit CPEs
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "category": _categorize_product(" ".join(cpes[:5]), desc),
            "mitre_techniques": _map_to_mitre(desc, " ".join(cpes[:3])),
        })

    print(f"  NVD ({severity}, {days}d): {len(vulns)} CVEs")
    return vulns


# ─── MITRE ATT&CK ────────────────────────────────────────────

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def fetch_mitre_attack():
    """Fetch MITRE ATT&CK technique catalog."""
    cache = CACHE_DIR / "mitre_attack.json"
    if cache.exists() and (time.time() - cache.stat().st_mtime) < 604800:  # 7 day cache
        data = json.loads(cache.read_text())
    else:
        r = requests.get(MITRE_STIX_URL, timeout=60)
        r.raise_for_status()
        data = r.json()
        cache.write_text(json.dumps(data, indent=2))

    techniques = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue
        
        ext_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                break
        
        if not ext_id:
            continue

        tactics = [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])]
        platforms = obj.get("x_mitre_platforms", [])
        data_sources = obj.get("x_mitre_data_sources", [])
        
        techniques.append({
            "source": "mitre_attack",
            "technique_id": ext_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": platforms,
            "data_sources": data_sources,
            "subtechnique": "." in ext_id,
            "severity": _mitre_severity(tactics),
        })

    print(f"  MITRE ATT&CK: {len(techniques)} techniques")
    return techniques


def _mitre_severity(tactics):
    """Map ATT&CK tactics to severity."""
    critical_tactics = {"impact", "exfiltration", "command-and-control"}
    high_tactics = {"initial-access", "execution", "privilege-escalation", "credential-access", "lateral-movement"}
    if any(t in critical_tactics for t in tactics):
        return "critical"
    if any(t in high_tactics for t in tactics):
        return "high"
    return "medium"


# ─── Emerging Threat Categories ──────────────────────────────

EMERGING_CATEGORIES = {
    "ai_llm_attacks": {
        "name": "AI/LLM Attack Detection",
        "description": "Detection rules for AI-specific attacks: prompt injection, model manipulation, data exfiltration, training data extraction",
        "techniques": [
            {"id": "AI-PI-001", "name": "Direct Prompt Injection", "severity": "critical"},
            {"id": "AI-PI-002", "name": "Indirect Prompt Injection", "severity": "critical"},
            {"id": "AI-PI-003", "name": "System Prompt Extraction", "severity": "high"},
            {"id": "AI-PI-004", "name": "Jailbreak Attempt", "severity": "critical"},
            {"id": "AI-PI-005", "name": "Token Smuggling", "severity": "high"},
            {"id": "AI-DX-001", "name": "Training Data Extraction", "severity": "critical"},
            {"id": "AI-DX-002", "name": "Model Inversion Attack", "severity": "high"},
            {"id": "AI-DX-003", "name": "PII Disclosure via LLM", "severity": "critical"},
            {"id": "AI-DX-004", "name": "Credential Leakage in AI Response", "severity": "critical"},
            {"id": "AI-MM-001", "name": "Temperature Manipulation", "severity": "medium"},
            {"id": "AI-MM-002", "name": "Max Tokens Abuse", "severity": "medium"},
            {"id": "AI-MM-003", "name": "Parameter Manipulation", "severity": "medium"},
            {"id": "AI-SM-001", "name": "AI Supply Chain Attack", "severity": "critical"},
            {"id": "AI-SM-002", "name": "Model Poisoning Detection", "severity": "critical"},
            {"id": "AI-RG-001", "name": "AI Governance Policy Violation", "severity": "medium"},
            {"id": "AI-RG-002", "name": "AI Bias Detection", "severity": "medium"},
        ]
    },
    "supply_chain": {
        "name": "Supply Chain Attack Detection",
        "description": "Detection rules for software supply chain attacks: dependency confusion, typosquatting, compromised packages",
        "techniques": [
            {"id": "SC-001", "name": "Dependency Confusion Attack", "severity": "critical"},
            {"id": "SC-002", "name": "Typosquatting Package Install", "severity": "high"},
            {"id": "SC-003", "name": "Compromised CI/CD Pipeline", "severity": "critical"},
            {"id": "SC-004", "name": "Malicious NPM/PyPI Package", "severity": "critical"},
            {"id": "SC-005", "name": "Container Image Tampering", "severity": "critical"},
            {"id": "SC-006", "name": "Compromised Update Server", "severity": "critical"},
            {"id": "SC-007", "name": "Build Pipeline Injection", "severity": "high"},
            {"id": "SC-008", "name": "Secret Leakage in CI Logs", "severity": "high"},
            {"id": "SC-009", "name": "Unsigned Artifact Deployment", "severity": "medium"},
            {"id": "SC-010", "name": "Dependency Version Pinning Bypass", "severity": "high"},
        ]
    },
    "cloud_native": {
        "name": "Cloud-Native Attack Detection",
        "description": "Kubernetes, container, serverless, and cloud-specific attack detection",
        "techniques": [
            {"id": "CN-001", "name": "Container Escape via Privileged Pod", "severity": "critical"},
            {"id": "CN-002", "name": "Kubernetes RBAC Privilege Escalation", "severity": "critical"},
            {"id": "CN-003", "name": "Serverless Function Injection", "severity": "high"},
            {"id": "CN-004", "name": "Cloud Metadata Service SSRF", "severity": "critical"},
            {"id": "CN-005", "name": "IAM Role Assumption Chain", "severity": "high"},
            {"id": "CN-006", "name": "S3 Bucket Policy Misconfiguration", "severity": "high"},
            {"id": "CN-007", "name": "ECS Task Definition Tampering", "severity": "high"},
            {"id": "CN-008", "name": "Lambda Environment Variable Exfiltration", "severity": "critical"},
            {"id": "CN-009", "name": "Kubernetes Secret Decryption", "severity": "critical"},
            {"id": "CN-010", "name": "Service Mesh Policy Bypass", "severity": "high"},
        ]
    },
    "ransomware": {
        "name": "Ransomware Detection",
        "description": "Detection rules for ransomware indicators: encryption patterns, C2 behavior, lateral movement preceding ransomware deployment",
        "techniques": [
            {"id": "RW-001", "name": "Mass File Encryption Pattern", "severity": "critical"},
            {"id": "RW-002", "name": "Shadow Copy Deletion", "severity": "critical"},
            {"id": "RW-003", "name": "Ransom Note Creation", "severity": "critical"},
            {"id": "RW-004", "name": "Volume Shadow Copy Tampering", "severity": "critical"},
            {"id": "RW-005", "name": "Backup Deletion via Vssadmin", "severity": "critical"},
            {"id": "RW-006", "name": "Ransomware C2 Beacon Pattern", "severity": "critical"},
            {"id": "RW-007", "name": "Mimikatz Credential Dumping Pre-Encryption", "severity": "critical"},
            {"id": "RW-008", "name": "Lateral Movement via PsExec/WMI", "severity": "high"},
            {"id": "RW-009", "name": "Scheduled Task Creation for Encryption", "severity": "high"},
            {"id": "RW-010", "name": "Registry Run Key Persistence for Ransomware", "severity": "high"},
        ]
    },
    "zero_day": {
        "name": "Zero-Day Vulnerability Detection",
        "description": "Behavioral detection rules for unknown zero-day exploitation patterns",
        "techniques": [
            {"id": "ZD-001", "name": "Unexpected Process Execution from Web Directory", "severity": "critical"},
            {"id": "ZD-002", "name": "Anomalous Child Process from Service", "severity": "high"},
            {"id": "ZD-003", "name": "Unusual Network Connection from System Process", "severity": "high"},
            {"id": "ZD-004", "name": "Memory Injection Pattern Detection", "severity": "critical"},
            {"id": "ZD-005", "name": "Unexpected DLL Loading", "severity": "high"},
            {"id": "ZD-006", "name": "Abnormal Token Privilege Elevation", "severity": "critical"},
            {"id": "ZD-007", "name": "Process Hollowing Indicator", "severity": "critical"},
            {"id": "ZD-008", "name": "Reflective DLL Injection", "severity": "critical"},
            {"id": "ZD-009", "name": "Unusual Named Pipe Activity", "severity": "medium"},
            {"id": "ZD-010", "name": "Anomalous Service Installation", "severity": "high"},
        ]
    },
    "mobile_security": {
        "name": "Mobile Security Detection",
        "description": "Android and iOS specific attack detection: app repackaging, certificate pinning bypass, API tampering",
        "techniques": [
            {"id": "MB-001", "name": "App Repackaging Detection", "severity": "critical"},
            {"id": "MB-002", "name": "Certificate Pinning Bypass", "severity": "high"},
            {"id": "MB-003", "name": "API Traffic Tampering", "severity": "high"},
            {"id": "MB-004", "name": "Root/Jailbreak Detection Bypass", "severity": "high"},
            {"id": "MB-005", "name": "Debuggable App in Production", "severity": "critical"},
            {"id": "MB-006", "name": "Insecure Data Storage", "severity": "high"},
            {"id": "MB-007", "name": "Intent Redirection Attack", "severity": "high"},
            {"id": "MB-008", "name": "Clipboard Data Leakage", "severity": "medium"},
            {"id": "MB-009", "name": "Insecure WebView Implementation", "severity": "high"},
            {"id": "MB-010", "name": "Biometric Auth Bypass", "severity": "critical"},
        ]
    },
    "ics_ot": {
        "name": "ICS/OT Security Detection",
        "description": "Industrial Control Systems and Operational Technology attack detection",
        "techniques": [
            {"id": "ICS-001", "name": "Modbus Command Injection", "severity": "critical"},
            {"id": "ICS-002", "name": "S7comm Firmware Upload", "severity": "critical"},
            {"id": "ICS-003", "name": "OPC UA Authentication Bypass", "severity": "critical"},
            {"id": "ICS-004", "name": "PLC Logic Modification", "severity": "critical"},
            {"id": "ICS-005", "name": "HMI Unauthorized Access", "severity": "high"},
            {"id": "ICS-006", "name": "SCADA Protocol Anomaly", "severity": "high"},
            {"id": "ICS-007", "name": "Engineering Workstation Compromise", "severity": "critical"},
            {"id": "ICS-008", "name": "Safety Instrumented System Tampering", "severity": "critical"},
            {"id": "ICS-009", "name": "ICS Network Scanning", "severity": "medium"},
            {"id": "ICS-010", "name": "Historian Database Manipulation", "severity": "high"},
        ]
    },
}


def generate_emerging_rules():
    """Generate rule definitions for emerging threat categories."""
    rules = []
    for category, data in EMERGING_CATEGORIES.items():
        for tech in data["techniques"]:
            rules.append({
                "source": "emerging",
                "category": category,
                "id": tech["id"],
                "name": tech["name"],
                "severity": tech["severity"],
                "description": data["description"],
                "full_name": f"{data['name']}: {tech['name']}",
            })
    print(f"  Emerging threats: {len(rules)} rule templates")
    return rules


# ─── Pentest Technique Catalog ───────────────────────────────

PENTEST_CATEGORIES = {
    "reconnaissance": {
        "name": "Reconnaissance & OSINT",
        "techniques": [
            {"id": "PT-RECON-001", "name": "Active Directory Domain Enumeration", "severity": "medium", "description": "Detect AD enumeration via LDAP queries, DSQuery, BloodHound collection"},
            {"id": "PT-RECON-002", "name": "Network Service Discovery (Nmap/Masscan)", "severity": "medium", "description": "Detect port scanning patterns from Nmap, Masscan, Shodan"},
            {"id": "PT-RECON-003", "name": "DNS Zone Transfer Attempt", "severity": "high", "description": "Detect AXFR zone transfer attempts revealing internal DNS records"},
            {"id": "PT-RECON-004", "name": "Web Technology Fingerprinting", "severity": "medium", "description": "Detect Wappalyzer/WhatWeb-style fingerprinting probes"},
            {"id": "PT-RECON-005", "name": "Cloud Asset Enumeration", "severity": "high", "description": "Detect enumeration of S3 buckets, Azure blobs, GCS via automated tools"},
            {"id": "PT-RECON-006", "name": "SSL/TLS Certificate Reconnaissance", "severity": "low", "description": "Detect certificate transparency log scraping and subdomain discovery"},
            {"id": "PT-RECON-007", "name": "API Endpoint Discovery", "severity": "high", "description": "Detect automated API endpoint fuzzing and directory brute forcing"},
            {"id": "PT-RECON-008", "name": "Email Harvesting & Phishing Prep", "severity": "medium", "description": "Detect email enumeration from O365/Google via SMTP probing"},
            {"id": "PT-RECON-009", "name": "SNMP Community String Brute Force", "severity": "high", "description": "Detect SNMP community string brute forcing revealing device info"},
            {"id": "PT-RECON-010", "name": "Kubernetes API Server Recon", "severity": "high", "description": "Detect unauthorized Kubernetes API server queries"},
        ]
    },
    "initial_access": {
        "name": "Initial Access Techniques",
        "techniques": [
            {"id": "PT-IA-001", "name": "Phishing Link Detection", "severity": "critical", "description": "Detect credential harvesting links in email via URL reputation"},
            {"id": "PT-IA-002", "name": "Spear-Phishing Attachment", "severity": "critical", "description": "Detect malicious attachments exploiting Office, PDF, or LNK"},
            {"id": "PT-IA-003", "name": "Valid Account Abuse", "severity": "high", "description": "Detect impossible travel, unusual time, or new device logins"},
            {"id": "PT-IA-004", "name": "Exploit Public-Facing Application", "severity": "critical", "description": "Detect exploitation of CVEs in web apps, VPNs, firewalls"},
            {"id": "PT-IA-005", "name": "Supply Chain Compromise", "severity": "critical", "description": "Detect malicious package or compromised update delivery"},
            {"id": "PT-IA-006", "name": "VPN Appliance Exploitation", "severity": "critical", "description": "Detect attacks on VPN concentrators (Pulse Secure, Fortinet, etc.)"},
            {"id": "PT-IA-007", "name": "Trusted Relationship Abuse", "severity": "high", "description": "Detect lateral movement from MSP/consultant/supplier accounts"},
            {"id": "PT-IA-008", "name": "Drive-by Compromise", "severity": "high", "description": "Detect exploit kit activity and malicious iframe injection"},
            {"id": "PT-IA-009", "name": "External Remote Services Brute Force", "severity": "high", "description": "Detect password spraying against RDP, SSH, VPN, OWA"},
            {"id": "PT-IA-010", "name": "Hardware Additions", "severity": "medium", "description": "Detect rogue USB, pineapple WiFi, or hardware implant indicators"},
        ]
    },
    "execution": {
        "name": "Execution Techniques",
        "techniques": [
            {"id": "PT-EXEC-001", "name": "PowerShell Suspicious Execution", "severity": "critical", "description": "Detect encoded PowerShell, -bypass, hidden window, and download cradle patterns"},
            {"id": "PT-EXEC-002", "name": "WMI Remote Execution", "severity": "critical", "description": "Detect WMI-based remote command execution via wmiprvse"},
            {"id": "PT-EXEC-003", "name": "Scheduled Task/At Job Creation", "severity": "high", "description": "Detect suspicious scheduled task creation for persistence or execution"},
            {"id": "PT-EXEC-004", "name": "LSASS Memory Dumping", "severity": "critical", "description": "Detect procdump, comsvcs.dll minidump, or direct LSASS access"},
            {"id": "PT-EXEC-005", "name": "Living-off-the-Land Binary (LOLBins)", "severity": "high", "description": "Detect abuse of certutil, bitsadmin, mshta, msiexec for download/execution"},
            {"id": "PT-EXEC-006", "name": "CMSTP Execution", "severity": "high", "description": "Detect CMSTP.exe used for DLL execution and bypass"},
            {"id": "PT-EXEC-007", "name": "Remote Service Session Hijacking", "severity": "high", "description": "Detect RDP/Terminal Services session hijacking patterns"},
            {"id": "PT-EXEC-008", "name": "Container Admin Escape", "severity": "critical", "description": "Detect container breakout via privileged mode or volume mount"},
            {"id": "PT-EXEC-009", "name": "Kubernetes Exec into Pod", "severity": "high", "description": "Detect kubectl exec into sensitive pods"},
            {"id": "PT-EXEC-010", "name": "SQL Command Execution via Web App", "severity": "critical", "description": "Detect SQL injection leading to xp_cmdshell, LOAD_FILE, COPY commands"},
        ]
    },
    "persistence": {
        "name": "Persistence Techniques",
        "techniques": [
            {"id": "PT-PERS-001", "name": "Registry Run Key Modification", "severity": "high", "description": "Detect modification of HKLM/HKCU Run/RunOnce keys"},
            {"id": "PT-PERS-002", "name": "Scheduled Task Persistence", "severity": "high", "description": "Detect scheduled tasks created for persistence"},
            {"id": "PT-PERS-003", "name": "Service Creation for Persistence", "severity": "high", "description": "Detect new Windows service creation with unusual binary paths"},
            {"id": "PT-PERS-004", "name": "WMI Event Subscription", "severity": "critical", "description": "Detect WMI event filter/consumer binding for persistent execution"},
            {"id": "PT-PERS-005", "name": "DLL Search Order Hijacking", "severity": "high", "description": "Detect DLL planting in application directories"},
            {"id": "PT-PERS-006", "name": "Browser Extension Persistence", "severity": "medium", "description": "Detect malicious browser extensions maintaining access"},
            {"id": "PT-PERS-007", "name": "Kubernetes CronJob Persistence", "severity": "high", "description": "Detect suspicious CronJob creation in Kubernetes clusters"},
            {"id": "PT-PERS-008", "name": "Cloud IAM Backdoor", "severity": "critical", "description": "Detect rogue IAM role/policy creation for persistent access"},
            {"id": "PT-PERS-009", "name": "SSH Authorized Key Injection", "severity": "high", "description": "Detect unauthorized SSH key additions to authorized_keys"},
            {"id": "PT-PERS-010", "name": "Cron Job Persistence (Linux)", "severity": "high", "description": "Detect suspicious crontab modifications for persistence"},
        ]
    },
    "exfiltration": {
        "name": "Data Exfiltration Detection",
        "techniques": [
            {"id": "PT-EXFIL-001", "name": "DNS Tunneling Detection", "severity": "critical", "description": "Detect anomalous DNS query patterns indicating data exfiltration via DNS"},
            {"id": "PT-EXFIL-002", "name": "Large Data Transfer to Cloud Storage", "severity": "high", "description": "Detect bulk data uploads to S3/Azure Blob/GCS from unusual sources"},
            {"id": "PT-EXFIL-003", "name": "ICMP Data Exfiltration", "severity": "high", "description": "Detect oversized ICMP packets carrying data payloads"},
            {"id": "PT-EXFIL-004", "name": "HTTPS Data Exfiltration", "severity": "high", "description": "Detect anomalous HTTPS uploads to legitimate services (Google Drive, Dropbox)"},
            {"id": "PT-EXFIL-005", "name": "Email Data Exfiltration", "severity": "high", "description": "Detect bulk email forwarding rules or auto-forwarding to external addresses"},
            {"id": "PT-EXFIL-006", "name": "Database Bulk Export", "severity": "critical", "description": "Detect mysqldump/pg_dump/bulk SELECT with client-side export"},
            {"id": "PT-EXFIL-007", "name": "Screen Capture Data Theft", "severity": "medium", "description": "Detect frequent screenshot capture or screen recording activity"},
            {"id": "PT-EXFIL-008", "name": "Steganography Detection", "severity": "medium", "description": "Detect image files with embedded data via entropy analysis"},
            {"id": "PT-EXFIL-009", "name": "Web Shell Data Exfiltration", "severity": "critical", "description": "Detect file upload/download via web shell endpoints"},
            {"id": "PT-EXFIL-010", "name": "Clipboard Data Theft", "severity": "medium", "description": "Detect repeated clipboard access or copy-paste of sensitive patterns"},
        ]
    },
    "lateral_movement": {
        "name": "Lateral Movement Detection",
        "techniques": [
            {"id": "PT-LM-001", "name": "Pass-the-Hash Detection", "severity": "critical", "description": "Detect NTLM hash-based authentication without password"},
            {"id": "PT-LM-002", "name": "Pass-the-Ticket Detection", "severity": "critical", "description": "Detect Kerberos ticket reuse from different source machines"},
            {"id": "PT-LM-003", "name": "Lateral Movement via PsExec", "severity": "high", "description": "Detect PsExec/WMIExec/SmbExec remote service installation"},
            {"id": "PT-LM-004", "name": "SSH Lateral Movement", "severity": "high", "description": "Detect SSH key-based lateral movement patterns"},
            {"id": "PT-LM-005", "name": "RDP Lateral Movement", "severity": "high", "description": "Detect unusual RDP sessions between workstations"},
            {"id": "PT-LM-006", "name": "Kubernetes Pod-to-Pod Lateral Movement", "severity": "high", "description": "Detect unexpected pod-to-pod communication patterns"},
            {"id": "PT-LM-007", "name": "DCSync Attack", "severity": "critical", "description": "Detect DCSync replication request from non-DC accounts"},
            {"id": "PT-LM-008", "name": "Golden Ticket Attack", "severity": "critical", "description": "Detect Kerberos TGT usage with abnormal lifetime or PAC"},
            {"id": "PT-LM-009", "name": "Kerberoasting", "severity": "high", "description": "Detect unusual Kerberos TGS-REQ patterns for SPN enumeration"},
            {"id": "PT-LM-010", "name": "ARP Spoofing Detection", "severity": "high", "description": "Detect ARP spoofing/gratuitous ARP for man-in-the-middle"},
        ]
    },
}


def generate_pentest_rules():
    """Generate pentest rule definitions."""
    rules = []
    for category, data in PENTEST_CATEGORIES.items():
        for tech in data["techniques"]:
            rules.append({
                "source": "pentest",
                "category": category,
                "id": tech["id"],
                "name": tech["name"],
                "severity": tech["severity"],
                "description": tech["description"],
                "full_name": f"{data['name']}: {tech['name']}",
            })
    print(f"  Pentest techniques: {len(rules)} rule templates")
    return rules


# ─── Main ────────────────────────────────────────────────────

def fetch_all():
    """Fetch all threat intel sources and produce normalized output."""
    print("=" * 60)
    print("THREAT INTEL INGESTION")
    print("=" * 60)
    
    all_intel = {}
    
    # CISA KEV
    print("\n[1/4] Fetching CISA KEV...")
    try:
        all_intel["cisa_kev"] = fetch_cisa_kev()
    except Exception as e:
        print(f"  ERROR: {e}")
        all_intel["cisa_kev"] = []
    
    # NVD recent critical CVEs
    print("\n[2/4] Fetching NVD recent critical CVEs (7 days)...")
    try:
        all_intel["nvd_critical"] = fetch_nvd_recent(days=7, severity="CRITICAL")
    except Exception as e:
        print(f"  ERROR: {e}")
        all_intel["nvd_critical"] = []
    
    # NVD recent high CVEs
    print("\n[2b/4] Fetching NVD recent high CVEs (7 days)...")
    try:
        all_intel["nvd_high"] = fetch_nvd_recent(days=7, severity="HIGH")
    except Exception as e:
        print(f"  ERROR: {e}")
        all_intel["nvd_high"] = []
    
    # MITRE ATT&CK
    print("\n[3/4] Fetching MITRE ATT&CK techniques...")
    try:
        all_intel["mitre_attack"] = fetch_mitre_attack()
    except Exception as e:
        print(f"  ERROR: {e}")
        all_intel["mitre_attack"] = []
    
    # Emerging categories
    print("\n[4/4] Generating emerging threat rules...")
    all_intel["emerging"] = generate_emerging_rules()
    
    # Pentest techniques
    print("\n[4b/4] Generating pentest technique rules...")
    all_intel["pentest"] = generate_pentest_rules()
    
    # Summary
    total = sum(len(v) for v in all_intel.values())
    print(f"\n{'=' * 60}")
    print(f"TOTAL THREAT INTEL ENTRIES: {total}")
    print(f"{'=' * 60}")
    for k, v in all_intel.items():
        print(f"  {k}: {len(v)}")
    
    # Save
    output = OUTPUT_DIR / f"threat_intel_{datetime.now().strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump(all_intel, f, indent=2)
    print(f"\nSaved to: {output}")
    
    # Also save as latest
    latest = OUTPUT_DIR / "threat_intel_latest.json"
    with open(latest, "w") as f:
        json.dump(all_intel, f, indent=2)
    print(f"Latest: {latest}")
    
    return all_intel


if __name__ == "__main__":
    fetch_all()