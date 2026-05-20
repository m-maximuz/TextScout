import json
import re
from collections import Counter
from pathlib import Path

SRC = Path("/home/maximuz/osint-project/data/02_processed/v3_0_cleaned.jsonl")

def load():
    with open(SRC) as f:
        return [json.loads(l) for l in f]

def user(r): return next(m["content"] for m in r["messages"] if m["role"] == "user")
def asst(r): return next(m["content"] for m in r["messages"] if m["role"] == "assistant")

def sample(recs, n=2, max_chars=400):
    out = []
    for r in recs[:n]:
        out.append(f"    USER  : {user(r)[:max_chars]}")
        out.append(f"    ASST  : {asst(r)[:max_chars]}")
        out.append("")
    return "\n".join(out)

print("=" * 60)
print("LOADING")
print("=" * 60)
data = load()
print(f"  {SRC.name}: {len(data):,} records")

print()
print("=" * 60)
print("SOURCE DISTRIBUTION")
print("=" * 60)
src_counts = Counter(r["source"] for r in data)
for s, n in src_counts.most_common():
    print(f"  {n:>6,}  {s}")

# === PROBLEM 1: telegram source emits "Multi-phase / Unclassified" + generic OPSEC boilerplate ===
print()
print("=" * 60)
print("PROBLEM 1: telegram source — 'Multi-phase / Unclassified' + boilerplate")
print("=" * 60)
tg = [r for r in data if r["source"] == "telegram"]
print(f"  total telegram records: {len(tg):,}")

bad_kc       = [r for r in tg if "multi-phase / unclassified" in asst(r).lower()]
bad_opsec    = [r for r in tg if "opsec intelligence:" in asst(r).lower() and "telegram" in asst(r).lower() and "monitored by both" in asst(r).lower()]
fab_source   = [r for r in tg if "vxunderground" in asst(r).lower() and "vxunderground" not in user(r).lower()]
short_asst   = [r for r in tg if len(asst(r)) < 400]

print(f"  contains 'Multi-phase / Unclassified' in assistant : {len(bad_kc):,} ({len(bad_kc)/max(len(tg),1)*100:.1f}%)")
print(f"  contains generic 'OPSEC Intelligence' boilerplate  : {len(bad_opsec):,} ({len(bad_opsec)/max(len(tg),1)*100:.1f}%)")
print(f"  fabricates 'vxunderground' attribution             : {len(fab_source):,}")
print(f"  assistant output < 400 chars (likely too thin)     : {len(short_asst):,} ({len(short_asst)/max(len(tg),1)*100:.1f}%)")
print()
print("  samples of 'Multi-phase / Unclassified' records:")
print(sample(bad_kc, n=2))

# === PROBLEM 2: MISP-template source — "Attribution Value: MISP Galaxy" boilerplate ===
print("=" * 60)
print("PROBLEM 2: MISP-template — 'Attribution Value: MISP Galaxy' boilerplate")
print("=" * 60)
misp_template = re.compile(r"attribution value:.*misp galaxy", re.IGNORECASE | re.DOTALL)
misp_recs = [r for r in data if misp_template.search(asst(r))]
print(f"  records matching MISP-Galaxy template: {len(misp_recs):,}")

if misp_recs:
    by_source = Counter(r["source"] for r in misp_recs)
    print(f"  emitted by sources:")
    for s, n in by_source.most_common():
        total = src_counts[s]
        print(f"    {s:25} {n:>5,} / {total:>5,}  ({n/total*100:.1f}% of source)")

entry_template = [r for r in misp_recs if re.match(r"^\s*entry type:\s*(attack tool|threat actor|malware|tool)", asst(r), re.IGNORECASE)]
print(f"  also has 'Entry Type: ...' header pattern: {len(entry_template):,}")
print()
print("  samples:")
print(sample(misp_recs, n=2))

# === PROBLEM 3: hf_cyber_v1 — degenerate <think> tag outputs ===
print("=" * 60)
print("PROBLEM 3: hf_cyber_v1 — <think> CoT format + generation degeneracy")
print("=" * 60)
hf_cyber = [r for r in data if r["source"] == "hf_cyber_v1"]
print(f"  total hf_cyber_v1 records: {len(hf_cyber):,}")

with_think  = [r for r in hf_cyber if "<think>" in asst(r).lower()]
long_asst   = [r for r in hf_cyber if len(asst(r)) > 3000]

print(f"  assistant contains <think> tag : {len(with_think):,} ({len(with_think)/max(len(hf_cyber),1)*100:.1f}%)")
print(f"  assistant > 3000 chars         : {len(long_asst):,} ({len(long_asst)/max(len(hf_cyber),1)*100:.1f}%)")
print()
print("  samples of <think>-tagged records:")
print(sample(with_think, n=2, max_chars=300))

# === Quick cross-check: are these the only 3 problem sources, or are bad templates elsewhere? ===
print("=" * 60)
print("CROSS-CHECK: bad templates leaking into other sources")
print("=" * 60)
for tpl_name, pattern in [
    ("'Multi-phase / Unclassified'", lambda r: "multi-phase / unclassified" in asst(r).lower()),
    ("'Attribution Value: MISP Galaxy'", lambda r: bool(misp_template.search(asst(r)))),
    ("'<think>' tag", lambda r: "<think>" in asst(r).lower()),
]:
    hits = [r for r in data if pattern(r)]
    by_src = Counter(r["source"] for r in hits)
    print(f"  {tpl_name}: total={len(hits):,}")
    for s, n in by_src.most_common(5):
        print(f"    {s:25} {n:>5,}")

# === VERDICT ===
print()
print("=" * 60)
print("VERDICT — proposed v3.2 cleanup")
print("=" * 60)
proposed_drops = 0
if bad_kc:
    print(f"  drop {len(bad_kc):,} telegram records with 'Multi-phase / Unclassified'")
    proposed_drops += len(bad_kc)
if misp_recs:
    print(f"  drop {len(misp_recs):,} records with MISP-Galaxy boilerplate template")
    proposed_drops += len(misp_recs)
if with_think:
    print(f"  drop {len(with_think):,} hf_cyber_v1 records with <think> tags")
    proposed_drops += len(with_think)
print()
print(f"  total proposed drops: {proposed_drops:,} of {len(data):,} ({proposed_drops/len(data)*100:.1f}%)")
print(f"  remaining: ~{len(data)-proposed_drops:,}")
