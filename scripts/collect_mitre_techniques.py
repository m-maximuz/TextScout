import requests
import json
import os
from collections import defaultdict

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTDIR = os.path.expanduser("~/osint-project/data/04_curation_v2_4")
TECH_OUT = os.path.join(OUTDIR, "mitre_techniques_raw.jsonl")
SOFT_OUT = os.path.join(OUTDIR, "mitre_software_raw.jsonl")


def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def collect():
    print("[*] Downloading MITRE ATT&CK enterprise STIX bundle...")
    bundle = requests.get(STIX_URL, timeout=120).json()["objects"]

    techniques, software, groups = {}, {}, {}
    for obj in bundle:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        t = obj.get("type")
        if t == "attack-pattern":
            techniques[obj["id"]] = obj
        elif t == "malware" or t == "tool":
            software[obj["id"]] = obj
        elif t == "intrusion-set":
            groups[obj["id"]] = obj

    # software -> groups that use it
    soft_groups = defaultdict(list)
    for obj in bundle:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref"), obj.get("target_ref")
        if src in groups and tgt in software:
            soft_groups[tgt].append(groups[src].get("name", ""))

    os.makedirs(OUTDIR, exist_ok=True)
    nt = 0
    with open(TECH_OUT, "w", encoding="utf-8") as f:
        for obj in techniques.values():
            aid = attack_id(obj)
            if not aid or not obj.get("description"):
                continue
            tactics = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])
                       if p.get("kill_chain_name") == "mitre-attack"]
            rec = {
                "attack_id": aid,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "detection": obj.get("x_mitre_detection", ""),
                "source": "mitre_technique",
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            nt += 1

    ns = 0
    with open(SOFT_OUT, "w", encoding="utf-8") as f:
        for sid, obj in software.items():
            aid = attack_id(obj)
            if not aid or not obj.get("description"):
                continue
            rec = {
                "attack_id": aid,
                "name": obj.get("name", ""),
                "type": obj.get("type", ""),
                "description": obj.get("description", ""),
                "platforms": obj.get("x_mitre_platforms", []),
                "used_by_groups": sorted(set(g for g in soft_groups.get(sid, []) if g)),
                "source": "mitre_software",
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            ns += 1

    print(f"[+] Wrote {nt} techniques -> {TECH_OUT}")
    print(f"[+] Wrote {ns} software/tools (with group attribution) -> {SOFT_OUT}")


if __name__ == "__main__":
    collect()
