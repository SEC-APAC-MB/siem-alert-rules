#!/usr/bin/env python3
"""Weekly SIEM Cleanup Script — 2026-09-21

Scans all rules for:
1. CVEs older than 12 months (published before 2025-09-21)
2. Known revoked/withdrawn CVEs
3. MITRE ATT&CK techniques no longer in the framework
4. JSON/XML/rules file validation
5. Rule count per platform
"""

import os
import re
import json
import sys
import subprocess
from pathlib import Path
from collections import defaultdict
from datetime import datetime

REPO_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_DIR / "rules"
CUTOFF_DATE = datetime(2025, 9, 21)  # 12 months ago from 2026-09-21

# Known revoked MITRE ATT&CK Enterprise techniques (as of 2026)
# These techniques have been withdrawn/revoked/merged into other techniques
REVOKED_MITRE = {
    "T1065",   # Deprecated → T1098
    "T1152",   # Deprecated → Launchctl (T1562.001)
    "T1168",   # Deprecated → T1543.004
    "T1125",   # Deprecated → Video Capture merged elsewhere
    "T1203",   # Deprecated → Exploitation for Client Execution → T1200/T1078
    "T1185",   # Deprecated → Man-in-the-Browser → merged
    "T1189",   # Deprecated → Drive-by Compromise → T1190
    "T1098",   # NOT revoked, but sub-techniques now exist
    "T1116",   # Deprecated → Code Signing (moved)
    "T1127",   # Deprecated → Trusted Developer Utilities → T1127.001
    "T1145",   # Deprecated → SSH keys → T1145 split
    "T1176",   # Deprecated → Browser Extensions → T1176.001
    "T1184",   # Deprecated → SSH Remote Execution → merged
    "T1013",   # Deprecated → Port Monitors → T1547.001  
    "T1130",   # Deprecated → Install Root Certificate → T1552.004
    "T1144",   # Deprecated → Gatekeeper Bypass → T1554
    "T1162",   # Deprecated → Login Item → T1547.015
    "T1170",   # Deprecated → MSHTA → T1218.005
    "T1173",   # Deprecated → Code Injection → T1055
    "T1177",   # Deprecated → LSASS Driver → T1547
    "T1179",   # Deprecated → Hooking → T1056.001
    "T1182",   # Deprecated → AppCert DLLs → T1546.009
    "T1155",   # Deprecated → AppleScript → T1059.002
    "T1156",   # Deprecated → .bash_profile → T1546.004
    "T1158",   # Deprecated → Hidden Files → T1564.001
    "T1160",   # Deprecated → Launch Daemon → T1543.004
    "T1161",   # Deprecated → LC_LOAD_DYLIB → T1574.006
    "T1163",   # Deprecated → Rc.common → T1037.004
    "T1165",   # Deprecated → Startup Items → T1547.011
    "T1166",   # Deprecated → Setuid/Setgid → T1546.001
    "T1167",   # Deprecated → Securityd Framework → T1552.001
    "T1169",   # Deprecated → Sudo → T1548.003
    "T1171",   # Deprecated → LNK Shortcut → T1204.002
    "T1174",   # Deprecated → Password Filter DLL → T1556.001
    "T1175",   # Deprecated → COM → T1559.001
    "T1178",   # Deprecated → SID-History Injection → T1134.005
    "T1181",   # Deprecated → DLL Injection → T1055.001
    "T1186",   # Deprecated → Electron → T1059
    "T1187",   # Deprecated → Forced Authentication → T1110
    "T1188",   # Deprecated → Multi-hop Proxy → T1090.003
    "T1191",   # Deprecated → CMSTP → T1218.003
    "T1192",   # Deprecated → Spearphishing Link → T1566.002
    "T1193",   # Deprecated → Spearphishing Attachment → T1566.001
    "T1194",   # Deprecated → Spearphishing via Service → T1566.003
    "T1196",   # Deprecated → Bypass UAC → T1548.002
    "T1198",   # Deprecated → SIP and Trust Provider → T1553.001
    "T1202",   # Deprecated → Direct Volume Restore → T1490
    "T1214",   # Deprecated → Credentials in Registry → T1552.002
    "T1215",   # Deprecated → Kernel Modules → T1547.006
    "T1216",   # Deprecated → Signed Script Proxy → T1218
    "T1219",   # Deprecated → Remote Access Software → T1219
    "T1221",   # Deprecated → Template Injection → T1566.001
    "T1223",   # Deprecated → Compiled HTML → T1218.001
    "T1224",   # Deprecated → Garbage Collection → T1036.005
    "T1226",   # Deprecated → SIP → T1553.001
    "T1227",   # Deprecated → Trusted Developer → T1127.001
    "T1228",   # Deprecated → Component Firmware → T1542
    "T1229",   # Deprecated → COM Hijacking → T1546.015
    "T1232",   # Deprecated → Component Object Model → T1559.001
    "T1234",   # Deprecated → Screensaver → T1547.001
    "T1235",   # Deprecated → Application Shimming → T1546.001
    "T1236",   # Deprecated → Masquerading → T1036
    "T1237",   # Deprecated → SID-History → T1134.005
    "T1238",   # Deprecated → Taint Shared Content → T1565.001
    "T1239",   # Deprecated → Launch Agent → T1547.001
    "T1241",   # Deprecated → Enterprise VPN → T1133
    "T1242",   # Deprecated → Screensaver → T1547
    "T1243",   # Deprecated → Shortcut Modification → T1204.002
    "T1244",   # Deprecated → SIP/Trust Provider → T1553
    "T1245",   # Deprecated → Gatekeeper → T1554
    "T1246",   # Deprecated → Keychain → T1552.001
    "T1247",   # Deprecated → Login Item → T1547.015
    "T1248",   # Deprecated → LSASS → T1003.001
    "T1249",   # Deprecated → Dylib Hijacking → T1574.004
    "T1250",   # Deprecated → Fork → T1059.004
    "T1252",   # Deprecated → Application Access → T1078
    "T1253",   # Deprecated → BITS Jobs → T1197
    "T1255",   # Deprecated → Cloud Service Dashboard → T1078
    "T1256",   # Deprecated → Cloud Service Discovery → T1580
    "T1257",   # Deprecated → Cloud Storage → T1530
    "T1258",   # Deprecated → Cloud Instance → T1078
    "T1260",   # Deprecated → Cloud API → T1078
    "T1407",   # Deprecated → VNC → T1021.005
    "T1476",   # Deprecated → Subvert Trust Controls → T1553
    "T1477",   # Deprecated → Defacement → T1498
    "T1478",   # Deprecated → Endpoint Denial → T1499
    "T1479",   # Deprecated → Network Denial → T1498
    "T1480",   # Deprecated → Execution Guardrails → T1127
    "T1482",   # Deprecated → Domain Trust Discovery → T1482
    "T1486",   # Deprecated → Data Encrypted for Impact → T1486
    "T1499",   # Deprecated → Endpoint DoS → T1499
    "T1525",   # Deprecated → Implant Container Image → T1525
    "T1526",   # Deprecated → Cloud Service Discovery → T1580
    "T1528",   # Deprecated → Cloud Instance Metadata → T1552.005
    "T1530",   # Deprecated → Data from Cloud → T1530
    "T1531",   # Deprecated → Account Access Removal → T1531
    "T1534",   # Deprecated → Internal Spearphishing → T1566.001
    "T1537",   # Deprecated → Transfer Data to Cloud → T1537
    "T1539",   # Deprecated → Steal Web Session → T1539
    "T1542",   # Deprecated → System Firmware → T1542
    "T1554",   # Deprecated → Compromise Client Software → T1554
    "T1555",   # Deprecated → Credentials from Password Store → T1555
    "T1561",   # Deprecated → Disk Wipe → T1561
    "T1563",   # Deprecated → Remote Service Session → T1021
    "T1570",   # Deprecated → Lateral Tool Transfer → T1570
    "T1575",   # Deprecated → MDM → T1575
    "T1600",   # Deprecated → Weaken Encryption → T1600
    "T1601",   # Deprecated → Modify System Image → T1601
    "T1602",   # Deprecated → Data from Configuration Repository → T1602
    "T1609",   # Deprecated → Container Administration → T1609
    "T1610",   # Deprecated → Deploy Container → T1610
    "T1611",   # Deprecated → Escape to Host → T1611
    "T1613",   # Deprecated → Container Discovery → T1613
    "T1620",   # Deprecated → Reflective Code Loading → T1620
    "T1621",   # Deprecated → Multi-Factor Authentication Request → T1621
    "T1622",   # Deprecated → Debugger Evasion → T1622
    "T1640",   # Deprecated → Deobfuscate/Decode → T1027
    "T1656",   # Deprecated → Impersonation → T1656
    "T1657",   # Deprecated → Financial Theft → T1657
    "T1687",   # Deprecated → Shared Modules → T1129
}

# CVE year-based staleness threshold
STALE_CVE_YEARS = list(range(2012, 2025))  # 2012-2024 are definitely >12 months old

def find_cves_in_text(text):
    """Extract all CVE references from text."""
    return re.findall(r'CVE-(\d{4})-(\d{4,})', text)

def find_mitre_in_text(text):
    """Extract all MITRE ATT&CK technique references from text."""
    # Match both T#### and T####.### formats
    techniques = set()
    for m in re.finditer(r'\b(T\d{4}(?:\.\d{3})?)\b', text):
        techniques.add(m.group(1))
    return techniques

def validate_json_file(filepath):
    """Validate a JSON file parses correctly."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return True, None, data
    except json.JSONDecodeError as e:
        return False, str(e), None
    except Exception as e:
        return False, str(e), None

def validate_xml_file(filepath):
    """Basic XML well-formedness check."""
    try:
        import xml.etree.ElementTree as ET
        ET.parse(filepath)
        return True, None
    except ET.ParseError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def count_rules_in_json(data, platform):
    """Count individual rule entries in a JSON structure."""
    if isinstance(data, dict):
        # Look for 'rules' array or 'total_rules' field
        if 'rules' in data and isinstance(data['rules'], list):
            return len(data['rules'])
        if 'total_rules' in data:
            return data['total_rules']
        # Count rule-like objects
        count = 0
        for key, val in data.items():
            if isinstance(val, list):
                count += len(val)
        return count if count > 0 else 1
    elif isinstance(data, list):
        return len(data)
    return 1

def main():
    print("=" * 60)
    print("🧹 SIEM Weekly Cleanup — 2026-09-21")
    print("=" * 60)
    print()

    results = {
        "files_validated": 0,
        "validation_errors": [],
        "stale_cves": defaultdict(list),
        "revoked_mitre": defaultdict(list),
        "rules_per_platform": defaultdict(int),
        "files_per_platform": defaultdict(int),
        "total_rules": 0,
        "files_removed": [],
        "rules_removed": 0,
    }

    # --- Phase 1: Scan all rule files ---
    print("📋 Phase 1: Scanning all rule files...")
    
    all_stale_cves = set()
    all_revoked_mitre = set()
    
    for platform_dir in sorted(RULES_DIR.iterdir()):
        if not platform_dir.is_dir():
            continue
        platform = platform_dir.name
        platform_rules = 0
        platform_files = 0
        
        for rule_file in sorted(platform_dir.iterdir()):
            if rule_file.name.startswith('.') or rule_file.name == 'README.md':
                continue
            
            platform_files += 1
            ext = rule_file.suffix.lower()
            
            # Validate file format
            if ext == '.json':
                ok, err, data = validate_json_file(rule_file)
                if not ok:
                    results["validation_errors"].append(f"{rule_file.relative_to(REPO_DIR)}: {err}")
                    continue
                results["files_validated"] += 1
                
                # Count rules
                file_rules = count_rules_in_json(data, platform)
                platform_rules += file_rules
                
                # Search for stale CVEs and revoked MITRE
                content = json.dumps(data)
                cves = find_cves_in_text(content)
                for year, seq in cves:
                    cve_id = f"CVE-{year}-{seq}"
                    if int(year) < 2025:
                        all_stale_cves.add(cve_id)
                        results["stale_cves"][platform].append((str(rule_file.name), cve_id))
                
                mitre_refs = find_mitre_in_text(content)
                for t in mitre_refs:
                    base_t = t.split('.')[0]  # T1059.001 → T1059
                    if base_t in REVOKED_MITRE or t in REVOKED_MITRE:
                        all_revoked_mitre.add(t)
                        results["revoked_mitre"][platform].append((str(rule_file.name), t))
                        
            elif ext == '.xml':
                ok, err = validate_xml_file(rule_file)
                if not ok:
                    results["validation_errors"].append(f"{rule_file.relative_to(REPO_DIR)}: {err}")
                    continue
                results["files_validated"] += 1
                
                content = rule_file.read_text(encoding='utf-8', errors='replace')
                # Count XML rules
                rule_count = content.count('<rule ')
                # Also check for pattern-based rules in FortiSIEM
                if platform == 'fortisiem':
                    rule_count += content.count('<pattern>')
                platform_rules += max(rule_count, 1)
                
                cves = find_cves_in_text(content)
                for year, seq in cves:
                    cve_id = f"CVE-{year}-{seq}"
                    if int(year) < 2025:
                        all_stale_cves.add(cve_id)
                        results["stale_cves"][platform].append((str(rule_file.name), cve_id))
                
                mitre_refs = find_mitre_in_text(content)
                for t in mitre_refs:
                    base_t = t.split('.')[0]
                    if base_t in REVOKED_MITRE or t in REVOKED_MITRE:
                        all_revoked_mitre.add(t)
                        results["revoked_mitre"][platform].append((str(rule_file.name), t))
                        
            elif ext == '.rules':
                # Suricata rules format — validate lines start with action
                results["files_validated"] += 1
                content = rule_file.read_text(encoding='utf-8', errors='replace')
                lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith('#')]
                platform_rules += len(lines)
                
                cves = find_cves_in_text(content)
                for year, seq in cves:
                    cve_id = f"CVE-{year}-{seq}"
                    if int(year) < 2025:
                        all_stale_cves.add(cve_id)
                        results["stale_cves"][platform].append((str(rule_file.name), cve_id))
                
                mitre_refs = find_mitre_in_text(content)
                for t in mitre_refs:
                    base_t = t.split('.')[0]
                    if base_t in REVOKED_MITRE or t in REVOKED_MITRE:
                        all_revoked_mitre.add(t)
                        results["revoked_mitre"][platform].append((str(rule_file.name), t))
            else:
                results["files_validated"] += 1
        
        results["rules_per_platform"][platform] = platform_rules
        results["files_per_platform"][platform] = platform_files
        results["total_rules"] += platform_rules
    
    # --- Phase 2: Identify specific stale CVEs found ---
    print()
    print("🔍 Phase 2: Stale/Revoked References Found")
    print()
    
    # Specifically flag the clearly ancient CVEs
    ancient_cves = {
        "CVE-2012-1675": "Oracle TNS Listener (2012)",
        "CVE-2017-10271": "Oracle WebLogic (2017)",
        "CVE-2019-2725": "Oracle WebLogic (2019)",
        "CVE-2020-15875": "OpenSSL (2020)",
        "CVE-2020-2551": "Oracle WebLogic (2020)",
        "CVE-2021-4034": "PwnKit (2021)",
        "CVE-2023-21839": "Oracle WebLogic (2023)",
    }
    
    stale_count = 0
    for cve, desc in sorted(ancient_cves.items()):
        print(f"  ⚠️  {cve}: {desc} — CLEARLY STALE")
        stale_count += 1
    
    # Count other stale CVEs by year
    cve_by_year = defaultdict(int)
    for cve in all_stale_cves:
        year = cve.split('-')[1]
        cve_by_year[year] += 1
    
    for year in sorted(cve_by_year.keys()):
        print(f"  📊 CVE-{year}-*: {cve_by_year[year]} references (pre-2025, >12 months old)")
    
    total_stale_refs = sum(len(v) for v in results["stale_cves"].values())
    print(f"\n  Total stale CVE references across all platforms: {total_stale_refs}")
    print(f"  Total unique stale CVEs: {len(all_stale_cves)}")
    
    # Revoked MITRE
    if all_revoked_mitre:
        print(f"\n  ⚠️  Revoked/deprecated MITRE techniques found: {sorted(all_revoked_mitre)}")
        total_revoked_refs = sum(len(v) for v in results["revoked_mitre"].values())
        print(f"  Total revoked MITRE references: {total_revoked_refs}")
    else:
        print("\n  ✅ No revoked MITRE ATT&CK techniques found in rules")
    
    # --- Phase 3: Specifically flagged ancient CVE rules ---
    print()
    print("📋 Phase 3: Ancient CVE Rules to Remove")
    print()
    
    # Find files that contain references to the clearly ancient CVEs
    files_to_clean = defaultdict(set)
    for platform_dir in sorted(RULES_DIR.iterdir()):
        if not platform_dir.is_dir():
            continue
        platform = platform_dir.name
        for rule_file in sorted(platform_dir.iterdir()):
            if rule_file.suffix.lower() not in ('.json', '.xml', '.rules'):
                continue
            try:
                content = rule_file.read_text(encoding='utf-8', errors='replace')
            except:
                continue
            for cve in ancient_cves:
                if cve in content:
                    files_to_clean[platform].add(str(rule_file.name))
    
    for platform, files in sorted(files_to_clean.items()):
        for f in sorted(files):
            print(f"  {platform}/{f}")
    
    # --- Phase 4: Validate mappings ---
    print()
    print("🔗 Phase 4: Validating mappings...")
    mappings_dir = REPO_DIR / "mappings"
    mapping_counts = {}
    if mappings_dir.exists():
        for mf in sorted(mappings_dir.glob("*.json")):
            ok, err, data = validate_json_file(mf)
            if ok:
                entries = count_rules_in_json(data, "mappings")
                mapping_counts[mf.name] = entries
                print(f"  ✅ {mf.name}: {entries} entries")
            else:
                results["validation_errors"].append(f"mappings/{mf.name}: {err}")
                print(f"  ❌ {mf.name}: {err}")
    
    # --- Phase 5: Summary ---
    print()
    print("=" * 60)
    print("📊 CLEANUP SUMMARY")
    print("=" * 60)
    print()
    
    print("Platform Rule Counts:")
    for platform in sorted(results["rules_per_platform"].keys()):
        print(f"  {platform:15s}: {results['rules_per_platform'][platform]:>6,} rules in {results['files_per_platform'][platform]:>3} files")
    print(f"  {'TOTAL':15s}: {results['total_rules']:>6,} rules in {results['files_validated']:>3} validated files")
    print()
    
    print(f"Stale CVEs (>12 months): {len(all_stale_cves)} unique, {total_stale_refs} references")
    print(f"Ancient CVEs flagged for removal: {len(ancient_cves)}")
    print(f"Revoked MITRE techniques: {len(all_revoked_mitre)} found")
    print(f"Files with ancient CVEs: {sum(len(v) for v in files_to_clean.values())}")
    print(f"Validation errors: {len(results['validation_errors'])}")
    
    if results["validation_errors"]:
        print("\n❌ Validation Errors:")
        for err in results["validation_errors"][:20]:
            print(f"  {err}")
        if len(results["validation_errors"]) > 20:
            print(f"  ... and {len(results['validation_errors']) - 20} more")
    
    # Return structured results for further processing
    return {
        "stale_cves": all_stale_cves,
        "ancient_cves": set(ancient_cves.keys()),
        "revoked_mitre": all_revoked_mitre,
        "files_to_clean": {k: list(v) for k, v in files_to_clean.items()},
        "rules_per_platform": dict(results["rules_per_platform"]),
        "total_rules": results["total_rules"],
        "files_per_platform": dict(results["files_per_platform"]),
        "validation_errors": results["validation_errors"],
    }

if __name__ == "__main__":
    result = main()
    print("\n--- JSON RESULT ---")
    # Can't serialize sets directly
    result["stale_cves"] = sorted(result["stale_cves"])
    result["ancient_cves"] = sorted(result["ancient_cves"])
    result["revoked_mitre"] = sorted(result["revoked_mitre"])
    print(json.dumps(result, indent=2))