import json
import re
import sys
from collections import defaultdict

CLEANED = sys.argv[1] if len(sys.argv) > 1 else "data/02_processed/v3_3_cleaned.jsonl"

PATTERNS = {
    "cve": re.compile(r"CVE-\d{4}-\d{3,7}", re.I),
    "ttp": re.compile(r"T\d{4}(?:\.\d{3})?"),
    "ip": re.compile(r"\b(?:\d{1,3}[.\[\]]+){3}\d{1,3}\b"),
    "domain": re.compile(r"\b[a-z0-9-]+(?:\[?\.\]?[a-z0-9-]+)*\[?\.\]?[a-z]{2,}\b", re.I),
    "hash": re.compile(r"\b[0-9a-f]{32,64}\b", re.I),
}


def defang_norm(s):
    return s.lower().replace("[.]", ".").replace("[", "").replace("]", "").replace("hxxp", "http")


def entities(text):
    out = set()
    for kind, pat in PATTERNS.items():
        for m in pat.findall(text):
            out.add((kind, defang_norm(m)))
    return out


def main():
    by_source = defaultdict(lambda: {"n": 0, "fab_records": 0, "asst_ent": 0, "fab_ent": 0})
    for line in open(CLEANED, encoding="utf-8"):
        r = json.loads(line)
        src = r["source"]
        user = r["messages"][1]["content"]
        asst = r["messages"][-1]["content"]
        ue, ae = entities(user), entities(asst)
        fab = {e for e in ae if e not in ue}
        d = by_source[src]
        d["n"] += 1
        d["asst_ent"] += len(ae)
        d["fab_ent"] += len(fab)
        if fab:
            d["fab_records"] += 1

    print(f"{'source':24} {'n':>6} {'%recs_w_fab':>11} {'fab_ent/asst_ent':>17}")
    print("-" * 62)
    for src, d in sorted(by_source.items(), key=lambda kv: kv[1]["fab_records"] / kv[1]["n"], reverse=True):
        pct = d["fab_records"] / d["n"]
        ratio = d["fab_ent"] / d["asst_ent"] if d["asst_ent"] else 0
        flag = "  <-- FABRICATION" if pct > 0.25 else ""
        print(f"{src:24} {d['n']:>6} {pct:>11.2f} {ratio:>17.2f}{flag}")
    print("\n%recs_w_fab = fraction of records whose assistant names an entity absent from user input.")
    print("Note: domain regex is noisy (catches things like github.io in canned advice) — read high values with the samples.")


if __name__ == "__main__":
    main()
