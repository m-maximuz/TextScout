import requests
import json
import os
from collections import defaultdict

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTDIR = os.path.expanduser("~/osint-project/data/04_curation_v2_4")
OUTPUT = os.path.join(OUTDIR, "mitre_groups_raw.jsonl")
PROBE = os.path.expanduser("~/osint-project/data/05_eval_probes/honesty_probe.jsonl")
TOP_TECHNIQUES = 12


PROBE_MITRE_ALIASES = {
    "sandworm": "sandworm team",
    "revil": "gold southfield",
    "equation group": "equation",
}


def probe_actor_ids():
    ids = set()
    for line in open(PROBE, encoding="utf-8"):
        r = json.loads(line)
        if r.get("category") == "real_actor":
            name = r["identifier"].lower()
            ids.add(name)
            if name in PROBE_MITRE_ALIASES:
                ids.add(PROBE_MITRE_ALIASES[name])
    return ids


def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def collect():
    print("[*] Downloading MITRE ATT&CK enterprise STIX bundle...")
    bundle = requests.get(STIX_URL, timeout=120).json()["objects"]

    groups = {}
    techniques = {}
    uses = defaultdict(list)

    for obj in bundle:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "intrusion-set":
            groups[obj["id"]] = obj
        elif t == "attack-pattern":
            techniques[obj["id"]] = obj

    for obj in bundle:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref"), obj.get("target_ref")
        if src in groups and tgt in techniques:
            uses[src].append(tgt)

    exclude = probe_actor_ids()
    os.makedirs(OUTDIR, exist_ok=True)
    count = 0
    skipped = []
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for gid, g in sorted(groups.items(), key=lambda kv: len(uses[kv[0]]), reverse=True):
            names = {g.get("name", "").lower(), *(a.lower() for a in g.get("aliases", []))}
            if names & exclude:
                skipped.append(g.get("name", ""))
                continue
            techs = []
            for tid in uses[gid]:
                tobj = techniques[tid]
                techs.append({"id": attack_id(tobj), "name": tobj.get("name", "")})
            techs = sorted(techs, key=lambda x: x["id"])[:TOP_TECHNIQUES]
            record = {
                "name": g.get("name", ""),
                "attack_id": attack_id(g),
                "aliases": g.get("aliases", []),
                "description": g.get("description", ""),
                "top_techniques": techs,
                "source": "real_actor",
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    sidecar = os.path.join(OUTDIR, "excluded_probe_actors.json")
    json.dump(sorted(skipped), open(sidecar, "w"), indent=2)
    print(f"[+] Wrote {count} group records -> {OUTPUT}")
    print(f"[+] Held out {len(skipped)} probe-matched actors -> {sidecar}")


if __name__ == "__main__":
    collect()
