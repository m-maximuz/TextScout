import json
import re
import os
import hashlib
from collections import defaultdict


def pick(variants, key):
    h = int(hashlib.md5(key.encode()).hexdigest(), 16)
    return variants[h % len(variants)]


KEV_STATUS = [
    "Exploitation Status: Confirmed active exploitation (CISA KEV).",
    "Exploitation Status: Listed in CISA KEV — exploited in the wild.",
    "Exploitation Status: CISA KEV-listed known exploited vulnerability.",
    "Exploitation Status: Actively exploited per CISA KEV.",
]

SRC = os.path.expanduser("~/osint-project/data/02_processed/v3_3_cleaned.jsonl")
OUT = os.path.expanduser("~/osint-project/data/02_processed/v3_4_cleaned.jsonl")

DROP_SOURCES = {"arxiv_security", "hf_wikipedia_security"}

KEEP = {
    "exploitdb": {"Exploit Type", "Target Platform", "Vulnerability Class", "CVE References"},
    "threatfox": {"Malware Family", "IOC Type", "Extracted Indicators"},
    "abusech": {"Threat Classification", "Extracted Indicators"},
    "atomic_red_team": {"ATT&CK Technique", "Target Platforms", "Execution Method", "Indicators"},
    "ghsa": {"Advisory", "Severity", "Vulnerability Class", "Supply Chain Target", "Technical Indicators"},
    "cisa_kev": {"Vulnerability", "Exploitation Status", "Required Remediation", "Technical Indicators"},
    "otx": {"Threat Actor", "Extracted Indicators"},
}
DROP = {
    "exploitdb": {"Kill Chain Phase", "Operational Assessment", "Red Team Application"},
    "threatfox": {"IOC Confidence", "Red Team Infrastructure Awareness", "OSINT Pivot", "C2 Framework Analysis"},
    "abusech": {"IOC Confidence", "Infrastructure Analysis", "Red Team Context", "Temporal Note"},
    "atomic_red_team": {"Kill Chain Phase", "Red Team Execution Context", "Detection Footprint"},
    "ghsa": {"Kill Chain Phase", "Supply Chain Attack Surface", "Red Team Application", "OSINT Pivot"},
    "cisa_kev": {"Vulnerability Class", "Attack Vector", "Kill Chain Phase", "Red Team Application", "OSINT Pivot"},
    "otx": {"Kill Chain Coverage", "Intelligence Confidence", "Red Team Application", "OSINT Pivot"},
}
CAP = {"exploitdb": 3500, "threatfox": 1500}

FILLER = {
    "exploitdb": [re.compile(r"^Vulnerability Class:\s*Unclassified")],
    "ghsa": [re.compile(r"^Vulnerability Class:\s*Unclassified")],
    "cisa_kev": [re.compile(r"^Required Remediation:\s*Apply updates per vendor instructions")],
}


def ghsa_remediation(user_text):
    out = []
    for label in ("Patches", "Workarounds"):
        m = re.search(rf"(?:^|\n){label}\s*\n+(.+?)(?=\n(?:Patches|Workarounds|Details|Impact|References|PoC)\b|\Z)",
                      user_text, re.S)
        if m:
            txt = re.sub(r"\s+", " ", m.group(1)).strip()
            if len(txt) > 8:
                out.append(f"Recommended Action ({label}): {txt[:280]}")
    return out

def deboilerplate(asst, src):
    keep_h, drop_h = KEEP[src], DROP[src]
    top = keep_h | drop_h
    fillers = FILLER.get(src, [])
    out, state = [], True
    for line in asst.split("\n"):
        head = line.split(":", 1)[0].strip()
        if head in top:
            state = head in keep_h
        if state and not any(p.match(line) for p in fillers):
            out.append(line)
    text = "\n".join(out)
    if src == "cisa_kev":
        m = re.search(r"CVE-\d{4}-\d{3,7}", text)
        key = m.group(0) if m else text
        text = re.sub(r"^Exploitation Status:.*$", pick(KEV_STATUS, key), text, flags=re.M)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def signature(rec, src):
    a = rec["messages"][2]["content"]

    def field(name):
        m = re.search(rf"^{re.escape(name)}:\s*(.+)$", a, re.M)
        return m.group(1).strip().lower() if m else ""

    if src == "exploitdb":
        return (field("Exploit Type"), field("Target Platform"), field("Vulnerability Class"))
    if src == "threatfox":
        has_ind = "Extracted Indicators" in a
        return (field("Malware Family"), field("IOC Type"), not has_ind)
    return None


def diversity_cap(records, src, cap):
    groups = defaultdict(list)
    for r in records:
        groups[signature(r, src)].append(r)
    # threatfox: within group, records with indicators (sig[2]=False) already grouped; round-robin groups
    order = sorted(groups, key=lambda k: -len(groups[k]))
    kept = []
    while len(kept) < cap and any(groups[k] for k in order):
        for k in order:
            if groups[k]:
                kept.append(groups[k].pop(0))
                if len(kept) >= cap:
                    break
    return kept


def main():
    by_source = defaultdict(list)
    for line in open(SRC, encoding="utf-8"):
        r = json.loads(line)
        by_source[r["source"]].append(r)

    out_records = []
    summary = []
    for src, recs in by_source.items():
        if src in DROP_SOURCES:
            summary.append((src, len(recs), 0, "DROPPED (100% canned, off-task)"))
            continue
        if src in KEEP:
            for r in recs:
                r["messages"][2]["content"] = deboilerplate(r["messages"][2]["content"], src)
                if src == "ghsa":
                    rem = ghsa_remediation(r["messages"][1]["content"])
                    if rem:
                        r["messages"][2]["content"] += "\n\n" + "\n\n".join(rem)
            n_before = len(recs)
            if src in CAP:
                recs = diversity_cap(recs, src, CAP[src])
            summary.append((src, n_before, len(recs), "de-boilerplated" + (" + capped" if src in CAP else "")))
        else:
            summary.append((src, len(recs), len(recs), "kept as-is"))
        out_records.extend(recs)

    with open(OUT, "w", encoding="utf-8") as f:
        for r in out_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"{'source':24} {'before':>7} {'after':>7}  action")
    print("-" * 60)
    for src, b, a, act in sorted(summary, key=lambda x: -x[2]):
        print(f"{src:24} {b:>7} {a:>7}  {act}")
    print("-" * 60)
    print(f"{'TOTAL':24} {sum(len(v) for v in by_source.values()):>7} {len(out_records):>7}")
    print(f"\nWrote -> {OUT}")


if __name__ == "__main__":
    main()
