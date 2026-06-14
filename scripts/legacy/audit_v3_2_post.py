"""Post-training audit for v3.2: find which sources teach the patterns
that produced SpaceX→APT28 fabrication, breachforus[.]com fabrication,
and hf_cyber_v1 repetition loops."""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

TRAIN = Path("/home/maximuz/osint-project/data/03_splits_v3.2/train.jsonl")

APT_NUMERIC = re.compile(r"\bAPT[\s-]?\d{1,3}\b", re.IGNORECASE)
APT_NAMED = re.compile(r"\bAPT[\s-][A-Z][a-zA-Z]+", re.IGNORECASE)
DOMAIN_DEFANG = re.compile(r"\b[a-z0-9-]+\[\.\][a-z]{2,}\b", re.IGNORECASE)
URL_DEFANG = re.compile(r"hxxps?://[^\s)>\]]+", re.IGNORECASE)

def load(path):
    with open(path) as f:
        for line in f:
            yield json.loads(line)

def msgs(rec):
    u = next((m["content"] for m in rec["messages"] if m["role"] == "user"), "")
    a = next((m["content"] for m in rec["messages"] if m["role"] == "assistant"), "")
    return u, a

# ============================================================
# AUDIT 1: APT attribution fabrication
# Which sources name an APT in assistant content when user didn't?
# ============================================================
print("=" * 78)
print("AUDIT 1: APT names in assistant NOT mentioned in user input")
print("=" * 78)

apt_fab_by_source = Counter()
apt_total_by_source = Counter()
apt_fab_examples = defaultdict(list)
all_apt_assistant = Counter()

for rec in load(TRAIN):
    src = rec.get("source", "unknown")
    u, a = msgs(rec)

    user_apts = set(m.group(0).lower().replace(" ", "").replace("-", "") for m in APT_NUMERIC.finditer(u))
    user_apts |= set(m.group(0).lower().replace(" ", "").replace("-", "") for m in APT_NAMED.finditer(u))
    asst_apts_raw = list(APT_NUMERIC.finditer(a)) + list(APT_NAMED.finditer(a))
    asst_apts = set(m.group(0).lower().replace(" ", "").replace("-", "") for m in asst_apts_raw)

    if asst_apts:
        apt_total_by_source[src] += 1
        for m in asst_apts_raw:
            all_apt_assistant[m.group(0)] += 1

    fabricated = asst_apts - user_apts
    if fabricated:
        apt_fab_by_source[src] += 1
        if len(apt_fab_examples[src]) < 2:
            apt_fab_examples[src].append({
                "fabricated": sorted(fabricated),
                "user_head": u[:200],
                "asst_head": a[:300],
            })

print(f"\n{'source':<25} {'fabricated':>12} {'has_apt':>10}  ratio")
for src in sorted(apt_fab_by_source, key=lambda s: -apt_fab_by_source[s]):
    n_fab = apt_fab_by_source[src]
    n_tot = apt_total_by_source[src]
    pct = (n_fab / n_tot * 100) if n_tot else 0
    print(f"{src:<25} {n_fab:>12} {n_tot:>10}  {pct:.1f}%")

print(f"\nTop 15 APT names appearing in assistant (across all sources):")
for name, n in all_apt_assistant.most_common(15):
    print(f"  {n:>5}  {name}")

print(f"\nWorst-offender examples:")
for src in sorted(apt_fab_by_source, key=lambda s: -apt_fab_by_source[s])[:3]:
    print(f"\n--- {src} ---")
    for ex in apt_fab_examples[src][:1]:
        print(f"  fabricated: {ex['fabricated']}")
        print(f"  user[:200]: {ex['user_head']!r}")
        print(f"  asst[:300]: {ex['asst_head']!r}")

# ============================================================
# AUDIT 2: Domain/URL fabrication
# Which sources put a defanged domain in assistant that's not in user input?
# ============================================================
print("\n" + "=" * 78)
print("AUDIT 2: Defanged domains in assistant NOT present in user input")
print("=" * 78)

dom_fab_by_source = Counter()
dom_total_by_source = Counter()
dom_fab_examples = defaultdict(list)
fabricated_domain_counter = Counter()

def normalize_dom(d):
    return d.lower().replace("[.]", ".").strip()

for rec in load(TRAIN):
    src = rec.get("source", "unknown")
    u, a = msgs(rec)

    u_norm = u.lower().replace("[.]", ".")
    user_doms = set(normalize_dom(m.group(0)) for m in DOMAIN_DEFANG.finditer(u))
    user_doms |= set(re.findall(r"\b[a-z0-9-]+\.[a-z]{2,}\b", u_norm))

    asst_doms_raw = list(DOMAIN_DEFANG.finditer(a))
    asst_doms = set(normalize_dom(m.group(0)) for m in asst_doms_raw)

    if asst_doms:
        dom_total_by_source[src] += 1

    fab = set()
    for d in asst_doms:
        if d in user_doms:
            continue
        # also accept partial match (subdomain leniency)
        if any(d in ud or ud in d for ud in user_doms):
            continue
        fab.add(d)

    if fab:
        dom_fab_by_source[src] += 1
        for d in fab:
            fabricated_domain_counter[d] += 1
        if len(dom_fab_examples[src]) < 2:
            dom_fab_examples[src].append({
                "fabricated": sorted(fab)[:5],
                "user_head": u[:200],
                "asst_head": a[:300],
            })

print(f"\n{'source':<25} {'fabricated':>12} {'has_dom':>10}  ratio")
for src in sorted(dom_fab_by_source, key=lambda s: -dom_fab_by_source[s]):
    n_fab = dom_fab_by_source[src]
    n_tot = dom_total_by_source[src]
    pct = (n_fab / n_tot * 100) if n_tot else 0
    print(f"{src:<25} {n_fab:>12} {n_tot:>10}  {pct:.1f}%")

print(f"\nTop 20 fabricated domains:")
for dom, n in fabricated_domain_counter.most_common(20):
    print(f"  {n:>5}  {dom}")

print(f"\nWorst-offender examples:")
for src in sorted(dom_fab_by_source, key=lambda s: -dom_fab_by_source[s])[:3]:
    print(f"\n--- {src} ---")
    for ex in dom_fab_examples[src][:1]:
        print(f"  fabricated: {ex['fabricated']}")
        print(f"  user[:200]: {ex['user_head']!r}")
        print(f"  asst[:300]: {ex['asst_head']!r}")

# ============================================================
# AUDIT 3: hf_cyber_v1 length distribution
# Long, low-diversity assistant outputs correlate with repetition
# ============================================================
print("\n" + "=" * 78)
print("AUDIT 3: hf_cyber_v1 assistant output length & repetition risk")
print("=" * 78)

lengths = []
repetitive = []
for rec in load(TRAIN):
    if rec.get("source") != "hf_cyber_v1":
        continue
    u, a = msgs(rec)
    lengths.append(len(a))

    # crude repetition detector: how much of the assistant text
    # is covered by the most common 50-char window?
    if len(a) >= 200:
        windows = Counter(a[i:i+50] for i in range(0, len(a) - 50, 10))
        top = windows.most_common(1)[0][1] if windows else 0
        density = top / max(1, len(a) // 10)
        if density > 0.05 and top >= 3:
            repetitive.append((density, top, len(a), a[:120]))

import statistics
print(f"\nhf_cyber_v1 train records: {len(lengths)}")
if lengths:
    print(f"  assistant chars min/med/p90/max: "
          f"{min(lengths)} / {int(statistics.median(lengths))} / "
          f"{sorted(lengths)[int(len(lengths)*0.9)]} / {max(lengths)}")
    over_2k = sum(1 for L in lengths if L > 2000)
    over_3k = sum(1 for L in lengths if L > 3000)
    print(f"  records >2000 chars: {over_2k} ({over_2k/len(lengths)*100:.1f}%)")
    print(f"  records >3000 chars: {over_3k} ({over_3k/len(lengths)*100:.1f}%)")

print(f"\nRecords with high-repetition windows in assistant: {len(repetitive)}")
for density, top, L, head in sorted(repetitive, reverse=True)[:5]:
    print(f"  density={density:.2f}  topwin={top}x  len={L}  head={head!r}")

print("\n" + "=" * 78)
print("DONE")
print("=" * 78)
