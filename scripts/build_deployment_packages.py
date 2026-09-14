#!/usr/bin/env python3
"""Build NIS2/DORA deployment packages from the canonical mappings + fixed rules."""
import json, glob, re, os
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(BASE, "rules")
MAPPINGS = os.path.join(BASE, "mappings")
DEPLOY = os.path.join(BASE, "deployments")

REGS = {
    "nis2": {"mapping": "nis2-mappings.json", "prefix": "NIS2", "label": "EV NIS2 Directive"},
    "dora": {"mapping": "dora-mappings.json", "prefix": "DORA", "label": "EV DORA Regulation"},
}


def load_rules(plat):
    idx = {}
    for p in glob.glob(os.path.join(RULES, plat, "*.json")):
        with open(p) as f:
            data = json.load(f)
        for r in data.get("rules", []):
            idx[r["rule_id"]] = r
    return idx


def article_from_refs(compliance_refs, prefix):
    arts = set()
    for cr in compliance_refs:
        m = re.search(rf"{re.escape(prefix)}-Art\.(\d+)", cr)
        if m:
            arts.add(f"Art.{m.group(1)}")
    return sorted(arts, key=lambda a: int(a.split(".")[1]))


def main():
    oracle_idx = load_rules("oracle")
    azure_idx = load_rules("azure")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stat = {}
    for reg, cfg in REGS.items():
        with open(os.path.join(MAPPINGS, cfg["mapping"])) as f:
            mapping = json.load(f)
        prefix = cfg["prefix"]
        articles_declared = mapping.get("articles", [])
        article_controls = {a["article"]: (a["title"], a.get("controls", [])) for a in articles_declared}

        resolved = []      # per mapping entry -> rule ids + refs
        unresolved = []
        for m in mapping.get("mappings", []):
            rid = m["rule_id"]
            refs = m.get("compliance_refs", [])
            arts = article_from_refs(refs, prefix)
            oci_id, az_id = f"OCI-{rid}", f"AZ-{rid}"
            entry = {
                "rule_id": rid,
                "name": m.get("name", rid),
                "compliance_refs": refs,
                "articles": arts,
                "oracle_rule_id": oci_id if oci_id in oracle_idx else None,
                "azure_rule_id": az_id if az_id in azure_idx else None,
            }
            if entry["oracle_rule_id"] or entry["azure_rule_id"]:
                resolved.append(entry)
            else:
                unresolved.append(entry)

        # bundle rules per platform
        for plat, key in (("oracle", "oracle_rule_id"), ("azure", "azure_rule_id")):
            bundled = []
            for e in resolved:
                rid = e[key]
                if not rid:
                    continue
                rule = dict(oracle_idx if plat == "oracle" else azure_idx).get(rid)
                if rule is None:
                    continue
                rule = dict(rule)
                rule["regulation_refs"] = e["compliance_refs"]
                rule["regulation_articles"] = e["articles"]
                bundled.append(rule)
            # ensure deterministic order by rule_id
            bundled.sort(key=lambda r: r["rule_id"])
            pkg_dir = os.path.join(DEPLOY, reg, plat)
            os.makedirs(pkg_dir, exist_ok=True)
            pkg = {
                "description": f"{cfg['label']} — Sentinel alert rules for {plat} (SIEM-alert-rules)",
                "regulation": prefix,
                "platform": plat,
                "version": "1.0.0",
                "generated": now,
                "total_rules": len(bundled),
                "rules": bundled,
            }
            with open(os.path.join(pkg_dir, "rules.json"), "w") as f:
                json.dump(pkg, f, indent=2)
                f.write("\n")

        # compliance matrix
        matrix_articles = []
        for a in articles_declared:
            art = a["article"]
            controls = a.get("controls", [])
            oci_ids = [e["oracle_rule_id"] for e in resolved
                       if art in e["articles"] and e["oracle_rule_id"]]
            az_ids = [e["azure_rule_id"] for e in resolved
                      if art in e["articles"] and e["azure_rule_id"]]
            matrix_articles.append({
                "article": art,
                "title": a.get("title", ""),
                "controls": controls,
                "oracle_rule_ids": sorted(set(oci_ids)),
                "total_oracle_rules": len(set(oci_ids)),
                "azure_rule_ids": sorted(set(az_ids)),
                "total_azure_rules": len(set(az_ids)),
            })
        matrix = {
            "regulation": prefix,
            "framework": cfg["label"],
            "generated": now,
            "version": "1.0.0",
            "articles": matrix_articles,
            "unresolved_mappings": [
                {"rule_id": e["rule_id"], "name": e["name"], "compliance_refs": e["compliance_refs"]}
                for e in unresolved
            ],
        }
        with open(os.path.join(DEPLOY, reg, "compliance-matrix.json"), "w") as f:
            json.dump(matrix, f, indent=2)
            f.write("\n")

        stat[reg] = {
            "mappings": len(mapping.get("mappings", [])),
            "resolved": len(resolved),
            "unresolved": len(unresolved),
            "oracle_rules": len([e for e in resolved if e["oracle_rule_id"]]),
            "azure_rules": len([e for e in resolved if e["azure_rule_id"]]),
        }
    print(json.dumps(stat, indent=2))


if __name__ == "__main__":
    main()