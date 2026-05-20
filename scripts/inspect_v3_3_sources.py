"""Hand-inspect the flagged sources from audit_v3_3_full.py.

For each candidate source the heuristic flagged, pull a few examples and answer
the question the metric alone can't answer:

  cve (100% cve-fab) — is the CVE in assistant absent from user input by
                       fabrication, or because the cleaning stripped a CVE
                       header from user input but kept it in assistant?

  mitre_attack (74% dup) — are the duplicates from one bad template or many?

  atomic_red_team (43% dup) — same.

  exploitdb (40% dup) — are dups deterministic Type×Platform templates or
                        identical full records?

  cisa_kev (93% hedge) — is "Multi-phase / Unclassified" really the hedge,
                         or just a different phrase matching the same regex?
"""

import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

IN_PATH = Path("/home/maximuz/osint-project/data/02_processed/v3_2_cleaned.jsonl")

random.seed(7)

def msgs(rec):
    u = next((m["content"] for m in rec["messages"] if m["role"] == "user"), "")
    a = next((m["content"] for m in rec["messages"] if m["role"] == "assistant"), "")
    return u, a

by_src = defaultdict(list)
with open(IN_PATH) as f:
    for line in f:
        r = json.loads(line)
        by_src[r["source"]].append(r)

# ============================================================
# CVE — verify CVE-fab is real fabrication, not stripped header
# ============================================================
print("=" * 100)
print("INSPECTION 1: cve — is CVE-in-assistant fabrication or stripped from user?")
print("=" * 100)

cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
records = by_src["cve"]
cve_fab_records = []
cve_match_records = []
for r in records:
    u, a = msgs(r)
    u_cves = {m.group(0).upper() for m in cve_re.finditer(u)}
    a_cves = {m.group(0).upper() for m in cve_re.finditer(a)}
    fab = a_cves - u_cves
    if fab:
        cve_fab_records.append((r, fab))
    if u_cves & a_cves:
        cve_match_records.append(r)

print(f"\n  cve records total: {len(records)}")
print(f"  records where asst CVE not in user: {len(cve_fab_records)}")
print(f"  records where at least one CVE matches: {len(cve_match_records)}")
print(f"\n  3 random fab records:")
for r, fab in random.sample(cve_fab_records, min(3, len(cve_fab_records))):
    u, a = msgs(r)
    print(f"\n  ---")
    print(f"  fab CVE: {fab}")
    print(f"  USER:\n    {u[:500]!r}")
    print(f"  ASST:\n    {a[:500]!r}")

# Look at the user content directly: does it contain the CVE in any form,
# even non-standard (e.g., a vendor advisory URL)?
print("\n  --- alternative form check: does user text contain the CVE digits anywhere? ---")
hits_digit = 0
for r, fab in cve_fab_records[:300]:
    u, _ = msgs(r)
    for c in fab:
        digits = c.split("-")[-1]  # last segment, e.g., "50690"
        year = c.split("-")[1]
        if digits in u or f"{year}-{digits}" in u:
            hits_digit += 1
            break
print(f"  in first 300 fab records, user text contains the CVE digits: {hits_digit} ({hits_digit/3:.0f}%)")

# ============================================================
# mitre_attack — examine the 74% duplicates
# ============================================================
print("\n" + "=" * 100)
print("INSPECTION 2: mitre_attack — what are the duplicates?")
print("=" * 100)

records = by_src["mitre_attack"]
asst_to_records = defaultdict(list)
for r in records:
    _, a = msgs(r)
    asst_to_records[a].append(r)

dup_groups = [(a, recs) for a, recs in asst_to_records.items() if len(recs) > 1]
dup_groups.sort(key=lambda x: -len(x[1]))
print(f"\n  mitre_attack records: {len(records)}")
print(f"  unique assistant texts: {len(asst_to_records)}")
print(f"  duplicate groups: {len(dup_groups)}")
print(f"\n  top 5 most-repeated assistant texts:")
for a, recs in dup_groups[:5]:
    print(f"\n  --- repeated {len(recs)} times ---")
    print(f"  asst: {a[:300]!r}")
    print(f"  first user: {msgs(recs[0])[0][:200]!r}")
    print(f"  second user: {msgs(recs[1])[0][:200]!r}")

# ============================================================
# atomic_red_team — examine the 43% duplicates
# ============================================================
print("\n" + "=" * 100)
print("INSPECTION 3: atomic_red_team — what are the duplicates?")
print("=" * 100)

records = by_src["atomic_red_team"]
asst_to_records = defaultdict(list)
for r in records:
    _, a = msgs(r)
    asst_to_records[a].append(r)

dup_groups = [(a, recs) for a, recs in asst_to_records.items() if len(recs) > 1]
dup_groups.sort(key=lambda x: -len(x[1]))
print(f"\n  atomic_red_team records: {len(records)}")
print(f"  unique assistant texts: {len(asst_to_records)}")
print(f"  duplicate groups: {len(dup_groups)}")
print(f"\n  top 3 most-repeated assistant texts:")
for a, recs in dup_groups[:3]:
    print(f"\n  --- repeated {len(recs)} times ---")
    print(f"  asst: {a[:300]!r}")
    print(f"  first user: {msgs(recs[0])[0][:200]!r}")

# ============================================================
# exploitdb — 40% dups, are they Type×Platform templates?
# ============================================================
print("\n" + "=" * 100)
print("INSPECTION 4: exploitdb — what are the 40% duplicates?")
print("=" * 100)

records = by_src["exploitdb"]
asst_to_records = defaultdict(list)
for r in records:
    _, a = msgs(r)
    asst_to_records[a].append(r)

dup_groups = [(a, recs) for a, recs in asst_to_records.items() if len(recs) > 1]
dup_groups.sort(key=lambda x: -len(x[1]))
print(f"\n  exploitdb records: {len(records)}")
print(f"  unique assistant texts: {len(asst_to_records)}")
print(f"  duplicate groups: {len(dup_groups)}")
print(f"\n  top 5 most-repeated assistant texts (templates):")
for a, recs in dup_groups[:5]:
    print(f"\n  --- repeated {len(recs)} times ---")
    print(f"  asst: {a[:250]!r}")
    print(f"  first user: {msgs(recs[0])[0][:120]!r}")
    print(f"  fifth user:  {msgs(recs[4])[0][:120]!r}" if len(recs) >= 5 else "")

# ============================================================
# cisa_kev — is the 93% hedge the same one AGENT.md said is OK?
# ============================================================
print("\n" + "=" * 100)
print("INSPECTION 5: cisa_kev — 93% hedge breakdown")
print("=" * 100)

records = by_src["cisa_kev"]
hedge_patterns = {
    "multi-phase / unclassified": 0,
    "unclassified — review": 0,
    "verify cvss": 0,
    "vulnerability class: unclassified": 0,
    "kill chain phase: multi-phase": 0,
}
for r in records:
    _, a = msgs(r)
    a_l = a.lower()
    for p in hedge_patterns:
        if p in a_l:
            hedge_patterns[p] += 1

print(f"\n  cisa_kev records: {len(records)}")
print(f"  hedge phrase counts:")
for p, n in sorted(hedge_patterns.items(), key=lambda x: -x[1]):
    print(f"    {n:>5}  '{p}'")

print(f"\n  3 random cisa_kev records:")
for r in random.sample(records, 3):
    u, a = msgs(r)
    print(f"\n  ---")
    print(f"  USER:\n    {u[:300]!r}")
    print(f"  ASST:\n    {a[:500]!r}")

# ============================================================
# abusech — narrow length, false positive check
# ============================================================
print("\n" + "=" * 100)
print("INSPECTION 6: abusech — narrow length, false positive check")
print("=" * 100)

records = by_src["abusech"]
print(f"\n  abusech records: {len(records)}")
print(f"\n  3 random abusech records:")
for r in random.sample(records, 3):
    u, a = msgs(r)
    print(f"\n  ---")
    print(f"  USER:\n    {u[:250]!r}")
    print(f"  ASST:\n    {a[:400]!r}")
