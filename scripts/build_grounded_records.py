import json
import os
import re
import random
import hashlib


def pick(variants, key):
    h = int(hashlib.md5(key.encode()).hexdigest(), 16)
    return variants[h % len(variants)]


NO_ATTR = [
    "No actor attribution provided in this report.",
    "The report does not attribute this activity to a named threat actor.",
    "No threat actor is named in the source; attribution is unspecified.",
    "Unattributed — the report identifies no specific adversary.",
    "No named actor in this report; attribution would require more sourcing.",
]
KEV_STATUS = [
    "Confirmed active exploitation (CISA KEV).",
    "Listed in CISA KEV — exploited in the wild.",
    "CISA KEV-listed known exploited vulnerability.",
    "Actively exploited per CISA KEV.",
]

# empty-lookup phrasings for fake-CVE negatives — modeled on the real NVD (totalResults: 0)
# and CISA KEV empty responses the deployed router will emit. Varied so the model keys on the
# empty body, not one phrasing.
NVD_EMPTY = [
    "NVD lookup: no record found.",
    "NVD: 0 matching records (totalResults: 0).",
    "NVD lookup returned no entry for this identifier.",
    "NVD: identifier not present in the database.",
    "NVD: query returned 0 results.",
    "NVD lookup: this CVE ID is not on file.",
    "NVD: no vulnerability record for this ID.",
    "NVD: not found.",
]
KEV_EMPTY = [
    "CISA KEV: not listed.",
    "CISA KEV: not present in the catalog.",
    "CISA KEV: absent.",
    "KEV catalog: no entry.",
    "CISA KEV: not in the Known Exploited Vulnerabilities catalog.",
]
CVE_INSTR = [
    "Assess this CVE for offensive relevance using only the record below.",
    "Assess this CVE for offensive relevance. Use only the record provided.",
    "Produce a red team assessment of this CVE from the record below only.",
]
# refusal-led (never prefixed with "CVE Assessment:" — that bleeds into the extraction format);
# each keeps the won't-fabricate / verify-the-ID honesty core.
CVE_REFUSAL = [
    "No authoritative record exists for {cid} — the NVD lookup returned nothing and it is not "
    "in CISA KEV. I will not fabricate a severity or vulnerability class for an identifier with "
    "no source record. Verify the CVE ID.",
    "No record found for {cid}. NVD has no entry and it is absent from CISA KEV, so there is "
    "nothing to assess — I won't invent a CVSS score, affected product, or exploitation status. "
    "Re-check the identifier.",
    "{cid} returns no data: empty NVD lookup, not in KEV. Without a source record I can't assess "
    "offensive relevance, and I won't fabricate one. Confirm the CVE ID or provide the advisory.",
    "I have no record for {cid}. The lookup came back empty (NVD: none; KEV: none). Assessing it "
    "would mean inventing details, which I won't do. This may be a typo, an unpublished or "
    "reserved ID, or a non-existent CVE.",
    "No NVD or KEV record backs {cid}, so I can't produce an evidence-grounded assessment. I "
    "won't guess a severity or vulnerability class. Verify the identifier against NVD.",
    "Lookup for {cid} returned nothing — no NVD entry, not KEV-listed. There is no basis to "
    "assess this CVE without fabricating, so I'm declining. Double-check the CVE ID.",
]

CUR = os.path.expanduser("~/osint-project/data/04_curation_v2_4")
OUT = os.path.join(CUR, "grounded_records.jsonl")

SYSTEM = (
    "You are an expert cybersecurity analyst specializing in Text OSINT and threat "
    "intelligence for red team operations. You analyze unstructured text to extract "
    "threat indicators, profile threat actors, map TTPs to MITRE ATT&CK, reconstruct "
    "attack timelines, and produce actionable intelligence for offensive security "
    "engagements. Work only from the record provided: extract and analyze what is present, "
    "and when a lookup is empty or no record is given, say so plainly instead of inventing "
    "details. Judge by the evidence in the input, not by whether a name looks familiar."
)

random.seed(7)

FAKE_ACTORS = [
    "APT-Nighthawk-19", "Crimson Basilisk", "APT-Verdant-63", "Glasswing Spider",
    "APT-Halcyon-7", "Obsidian Mantis", "APT-Solstice-44", "Pale Adder",
    "APT-Cobalt-Lynx-12", "Sable Tempest-X", "APT-Ferrous-88", "Hollow Cicada",
    "APT-Umbral-31", "Quartz Viper", "APT-Driftwood-5", "Iron Marmot",
]
def load_fake_cves():
    p = os.path.join(CUR, "verified_fake_cves.json")
    if not os.path.exists(p):
        raise SystemExit("verified_fake_cves.json missing — run scripts/verify_fake_cves.py first")
    return json.load(open(p))


def clean(text):
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def rec(user, assistant, source):
    return {"messages": [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": user},
        {"role": "assistant", "content": assistant},
    ], "source": source}


# ---- actors ----
def actor_positive(g):
    techs = g["top_techniques"]
    aliases = ", ".join(g["aliases"]) if g["aliases"] else "none recorded"
    tech_block = "; ".join(f"{t['id']} {t['name']}" for t in techs)
    user = (
        "Use only the MITRE ATT&CK record below to produce a red-team threat profile. "
        "Do not add any actor, technique, or attribution not present in the record.\n\n"
        "[MITRE ATT&CK Group lookup]\n"
        f"Name: {g['name']} ({g['attack_id']})\n"
        f"Aliases: {aliases}\n"
        f"Attributed techniques: {tech_block}\n"
        f"Description: {clean(g['description'])}"
    )
    background = " ".join(re.split(r"(?<=[.!?]) ", clean(g["description"]))[:2])
    tech_lines = "\n".join(f"- {t['id']} {t['name']}" for t in techs)
    assistant = (
        f"Threat Actor Profile: {g['name']} ({g['attack_id']})\n\n"
        f"Known Aliases: {aliases}\n\n"
        f"Background: {background}\n\n"
        f"Documented TTPs (MITRE ATT&CK):\n{tech_lines}\n\n"
        f"Attribution Confidence: Documented actor, MITRE ATT&CK {g['attack_id']}."
    )
    return rec(user, assistant, "real_actor")


def actor_negative(name):
    user = (
        "Use only the MITRE ATT&CK record below to produce a red-team threat profile. "
        "Do not add any actor, technique, or attribution not present in the record.\n\n"
        "[MITRE ATT&CK Group lookup]\n"
        f"Query: {name}\n"
        "Result: no matching group found."
    )
    assistant = (
        f"No authoritative record for \"{name}\". The MITRE ATT&CK lookup returned no "
        "matching group, so I cannot profile this actor without fabricating attribution. "
        "Provide a source report or indicators and I will analyze those directly."
    )
    return rec(user, assistant, "real_actor")


# ---- cves ----
def cve_positive(c):
    cwes = ", ".join(c.get("cwes", [])) or "see description"
    desc = c.get("nvd_description") or c.get("kev_description", "")
    summary = " ".join(re.split(r"(?<=[.!?]) ", desc)[:2])
    kev = pick(KEV_STATUS, c["cve_id"])
    lines = [
        f"CVE Assessment: {c['cve_id']}",
        f"Affected: {c.get('vendor','')} {c.get('product','')}".strip(),
        f"Severity (CVSS): {c.get('cvss','not provided')}",
        f"Vulnerability Class: {cwes}",
        f"Summary: {summary}",
        f"Exploitation Status: {kev}",
    ]
    ra = c.get("required_action", "")
    if ra and not ra.lower().startswith("apply updates per vendor"):
        lines.append(f"Required Remediation: {ra}")
    user = (
        "Assess this CVE for offensive relevance using only the record below. "
        "Do not add details not present.\n\n"
        "[CVE Record]\n"
        f"CVE: {c['cve_id']}\n"
        f"Name: {c.get('name','')}\n"
        f"Vendor/Product: {c.get('vendor','')} {c.get('product','')}\n"
        f"Description: {desc}\n"
        f"CVSS: {c.get('cvss','')}\n"
        f"CWE: {cwes}\n"
        f"KEV ransomware use: {c.get('ransomware_use','')}\n"
        f"Required action: {c.get('required_action','')}"
    )
    return rec(user, "\n\n".join(lines), "real_cve")


def cve_negative(cid):
    user = (
        f"{pick(CVE_INSTR, cid + 'i')}\n\n"
        "[CVE Record]\n"
        f"CVE: {cid}\n"
        f"{pick(NVD_EMPTY, cid + 'n')}\n"
        f"{pick(KEV_EMPTY, cid + 'k')}"
    )
    assistant = pick(CVE_REFUSAL, cid + "r").format(cid=cid)
    return rec(user, assistant, "real_cve")


# ---- otx pulses ----
def by_type(indicators):
    groups = {}
    for i in indicators:
        groups.setdefault(i["type"], []).append(i["indicator"])
    return groups


def otx_record(p):
    groups = by_type(p["indicators"])
    ind_in = "\n".join(f"  {t}: {', '.join(v[:15])}" for t, v in groups.items())
    attack = ", ".join(p["attack_ids"]) if p["attack_ids"] else "none tagged"
    mal = ", ".join(p["malware_families"]) if p["malware_families"] else "none named"
    adv = p["adversary"] if p["adversary"] else ""
    user = (
        "Analyze this threat intelligence report. Produce a structured red-team summary "
        "using only what the report states. Do not invent actors, malware, or indicators.\n\n"
        "[Threat Report]\n"
        f"Title: {p['name']}\n\n"
        f"{p['description']}\n\n"
        f"Reported indicators:\n{ind_in}\n"
        f"Analyst-tagged ATT&CK: {attack}\n"
        f"Malware families: {mal}\n"
        f"Attributed actor: {adv if adv else 'none specified'}\n"
        f"Targeted industries: {', '.join(p['industries']) or 'not specified'}\n"
        f"Targeted countries: {', '.join(p['targeted_countries']) or 'not specified'}"
    )
    ind_out = "\n".join(f"- {t}: {', '.join(v[:15])}" for t, v in groups.items()) or "- none provided"
    actor_line = adv if adv else pick(NO_ATTR, p["name"])
    parts = [
        f"Threat Report Analysis: {p['name']}",
        f"Malware / Tooling: {mal}",
        f"Threat Actor: {actor_line}",
        f"MITRE ATT&CK Techniques: {attack}",
        f"Extracted Indicators:\n{ind_out}",
    ]
    if p["industries"] or p["targeted_countries"]:
        parts.append(f"Targeting: industries [{', '.join(p['industries']) or 'n/a'}], "
                     f"countries [{', '.join(p['targeted_countries']) or 'n/a'}]")
    return rec(user, "\n\n".join(parts), "otx_pulse")


NO_GROUP = [
    "No threat group is documented using this in MITRE ATT&CK.",
    "MITRE ATT&CK records no specific group operating this tool.",
    "No documented actor attribution for this software in ATT&CK.",
]


def technique_record(t):
    tactics = ", ".join(t["tactics"]) or "not specified"
    platforms = ", ".join(t["platforms"]) or "not specified"
    desc = clean(t["description"])
    summary = " ".join(re.split(r"(?<=[.!?]) ", desc)[:3])
    user = (
        "Explain this MITRE ATT&CK technique and its offensive relevance. "
        "Use only the record provided.\n\n"
        "[MITRE ATT&CK Technique]\n"
        f"ID: {t['attack_id']}\n"
        f"Name: {t['name']}\n"
        f"Tactics: {tactics}\n"
        f"Platforms: {platforms}\n"
        f"Description: {desc}"
    )
    lines = [
        f"ATT&CK Technique: {t['name']} ({t['attack_id']})",
        f"Tactics: {tactics}",
        f"Platforms: {platforms}",
        f"How it works: {summary}",
    ]
    if t.get("detection"):
        det = " ".join(re.split(r"(?<=[.!?]) ", clean(t["detection"]))[:2])
        lines.append(f"Detection: {det}")
    return rec(user, "\n\n".join(lines), "mitre_technique")


def software_record(s):
    platforms = ", ".join(s["platforms"]) or "not specified"
    desc = clean(s["description"])
    summary = " ".join(re.split(r"(?<=[.!?]) ", desc)[:3])
    groups = s["used_by_groups"]
    if not groups:
        operators = pick(NO_GROUP, s["attack_id"])
    elif len(groups) <= 4:
        operators = "Documented in use by: " + ", ".join(groups) + "."
    else:
        operators = ("Commonly shared tooling — documented users include "
                     + ", ".join(groups[:6]) + f", and {len(groups) - 6} other groups. "
                     "Not exclusive to a single actor.")
    user = (
        "Explain this malware/tool and identify which threat actors use it. "
        "Use only the record provided.\n\n"
        "[MITRE ATT&CK Software]\n"
        f"ID: {s['attack_id']}\n"
        f"Name: {s['name']}\n"
        f"Type: {s['type']}\n"
        f"Platforms: {platforms}\n"
        f"Description: {desc}\n"
        f"Documented user groups: {', '.join(groups) if groups else 'none recorded'}"
    )
    lines = [
        f"Software: {s['name']} ({s['attack_id']}) — {s['type']}",
        f"Platforms: {platforms}",
        f"Capabilities: {summary}",
        f"Known Operators: {operators}",
    ]
    return rec(user, "\n\n".join(lines), "mitre_software")


def load(name):
    path = os.path.join(CUR, name)
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, encoding="utf-8")]


def main():
    out = []
    actors = load("mitre_groups_raw.jsonl")
    out += [actor_positive(g) for g in actors]
    out += [actor_negative(n) for n in FAKE_ACTORS]

    cves = [c for c in load("real_cve_raw.jsonl") if c.get("nvd_description") or c.get("kev_description")]
    fake_cves = load_fake_cves()
    out += [cve_positive(c) for c in cves]
    out += [cve_negative(c) for c in fake_cves]

    pulses = load("otx_pulses_raw.jsonl")
    random.shuffle(pulses)
    out += [otx_record(p) for p in pulses[:2500]]

    techniques = load("mitre_techniques_raw.jsonl")
    random.shuffle(techniques)
    out += [technique_record(t) for t in techniques[:600]]

    software = load("mitre_software_raw.jsonl")
    attributed = [s for s in software if s["used_by_groups"]]
    unattributed = [s for s in software if not s["used_by_groups"]]
    random.shuffle(attributed)
    random.shuffle(unattributed)
    out += [software_record(s) for s in attributed[:400] + unattributed[:100]]

    random.shuffle(out)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    from collections import Counter
    c = Counter(r["source"] for r in out)
    print(f"Wrote {len(out)} grounded records -> {OUT}")
    for s, n in c.most_common():
        print(f"  {n:>5}  {s}")
    print(f"  (actor negatives: {len(FAKE_ACTORS)}, cve negatives: {len(fake_cves)})")


if __name__ == "__main__":
    main()
