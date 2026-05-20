"""Full per-source audit on v3.2 cleaned data.

For every source, measure:
  - record count
  - assistant length distribution (catch the hf_cyber_v1-style truncation)
  - template duplication (top-200-char opening prefix concentration)
  - APT fabrication rate (asst names APT not in user)
  - domain fabrication rate (asst names defanged domain not in user)
  - CVE fabrication rate (asst names CVE not in user)
  - hash fabrication rate (asst has 32/40/64-hex not in user) — was v1 regression
  - over-hedge phrase rate ("Multi-phase / Unclassified", "verify CVSS", etc)
  - empty/near-empty assistant rate
  - generic refusal-template rate

Reads:  data/02_processed/v3_2_cleaned.jsonl
Writes: stdout summary + reports/audit_v3_3.json (per-source details)
"""

import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

IN_PATH = Path("/home/maximuz/osint-project/data/02_processed/v3_2_cleaned.jsonl")
OUT_JSON = Path("/home/maximuz/osint-project/reports/audit_v3_3.json")
OUT_JSON.parent.mkdir(parents=True, exist_ok=True)

APT_RE = re.compile(r"\bAPT[\s-]?[A-Za-z0-9][A-Za-z0-9-]*\b")
DOMAIN_DEFANG_RE = re.compile(r"\b[a-z0-9-]+\[\.\][a-z]{2,}\b", re.IGNORECASE)
DOMAIN_PLAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE)

HEDGE_PATTERNS = [
    "multi-phase / unclassified",
    "unclassified — review",
    "verify cvss",
    "vulnerability class: unclassified",
    "kill chain phase: multi-phase",
]

REFUSAL_MARKERS = [
    "i don't have data",
    "i don't have reliable information",
    "i'm not familiar with",
    "may be a typo",
    "may be a typo, misspelling, or fictional",
    "i cannot confirm",
    "i won't speculate",
    "i'd rather not speculate",
]

def normalize_apt(s):
    return re.sub(r"[\s\-]", "", s.lower())

def normalize_dom(s):
    return s.lower().replace("[.]", ".").strip()

def msgs(rec):
    u = next((m["content"] for m in rec["messages"] if m["role"] == "user"), "")
    a = next((m["content"] for m in rec["messages"] if m["role"] == "assistant"), "")
    return u, a

per_source_stats = defaultdict(lambda: {
    "count": 0,
    "asst_lens": [],
    "openings": Counter(),
    "asst_full_hash": Counter(),
    "apt_in_asst": 0,
    "apt_fabricated": 0,
    "dom_in_asst": 0,
    "dom_fabricated": 0,
    "cve_in_asst": 0,
    "cve_fabricated": 0,
    "hash_in_asst": 0,
    "hash_fabricated": 0,
    "has_hedge": 0,
    "is_refusal": 0,
    "asst_empty": 0,
    "asst_tiny": 0,
    "fab_apt_examples": [],
    "fab_dom_examples": [],
    "fab_cve_examples": [],
})

print(f"Reading {IN_PATH}...")
total = 0
with open(IN_PATH) as f:
    for line in f:
        total += 1
        r = json.loads(line)
        src = r.get("source", "unknown")
        s = per_source_stats[src]
        s["count"] += 1

        u, a = msgs(r)
        u_l, a_l = u.lower(), a.lower()
        s["asst_lens"].append(len(a))
        s["openings"][a[:200]] += 1
        s["asst_full_hash"][hash(a)] += 1

        if len(a.strip()) == 0:
            s["asst_empty"] += 1
        elif len(a.strip()) < 100:
            s["asst_tiny"] += 1

        # APT
        user_apts = {normalize_apt(m.group(0)) for m in APT_RE.finditer(u)}
        asst_apts = {normalize_apt(m.group(0)) for m in APT_RE.finditer(a)}
        if asst_apts:
            s["apt_in_asst"] += 1
        fab_apt = asst_apts - user_apts
        if fab_apt:
            s["apt_fabricated"] += 1
            if len(s["fab_apt_examples"]) < 2:
                s["fab_apt_examples"].append({"fab": sorted(fab_apt), "u": u[:150], "a": a[:250]})

        # domains (only defanged in assistant — that's the IOC pattern we care about)
        user_doms_plain = {normalize_dom(m.group(0)) for m in DOMAIN_PLAIN_RE.finditer(u)}
        user_doms_defang = {normalize_dom(m.group(0)) for m in DOMAIN_DEFANG_RE.finditer(u)}
        user_doms = user_doms_plain | user_doms_defang
        asst_doms_defang = {normalize_dom(m.group(0)) for m in DOMAIN_DEFANG_RE.finditer(a)}
        if asst_doms_defang:
            s["dom_in_asst"] += 1
        fab_dom = set()
        for d in asst_doms_defang:
            if d in user_doms:
                continue
            if any(d in ud or ud in d for ud in user_doms):
                continue
            fab_dom.add(d)
        if fab_dom:
            s["dom_fabricated"] += 1
            if len(s["fab_dom_examples"]) < 2:
                s["fab_dom_examples"].append({"fab": sorted(fab_dom)[:5], "u": u[:150], "a": a[:250]})

        # CVE
        user_cves = {m.group(0).upper() for m in CVE_RE.finditer(u)}
        asst_cves = {m.group(0).upper() for m in CVE_RE.finditer(a)}
        if asst_cves:
            s["cve_in_asst"] += 1
        fab_cve = asst_cves - user_cves
        if fab_cve:
            s["cve_fabricated"] += 1
            if len(s["fab_cve_examples"]) < 2:
                s["fab_cve_examples"].append({"fab": sorted(fab_cve), "u": u[:150], "a": a[:250]})

        # hash
        user_hashes = {m.group(0).lower() for m in HASH_RE.finditer(u)}
        asst_hashes = {m.group(0).lower() for m in HASH_RE.finditer(a)}
        if asst_hashes:
            s["hash_in_asst"] += 1
        if asst_hashes - user_hashes:
            s["hash_fabricated"] += 1

        # over-hedge phrases
        if any(p in a_l for p in HEDGE_PATTERNS):
            s["has_hedge"] += 1

        # refusal markers
        if any(m in a_l for m in REFUSAL_MARKERS):
            s["is_refusal"] += 1

print(f"loaded {total:,} records across {len(per_source_stats)} sources\n")

# === Compute summary per source ===
rows = []
for src, s in per_source_stats.items():
    n = s["count"]
    lens = s["asst_lens"]
    L_med = int(statistics.median(lens)) if lens else 0
    L_p10 = sorted(lens)[int(len(lens)*0.10)] if lens else 0
    L_p90 = sorted(lens)[int(len(lens)*0.90)] if lens else 0
    L_max = max(lens) if lens else 0
    # length narrowness = (p90 - p10) / median.  Low value = suspiciously uniform length (truncation).
    narrow = (L_p90 - L_p10) / L_med if L_med else 0

    # template concentration: largest opening-prefix bucket as % of records
    top_open_count, top_open = (s["openings"].most_common(1)[0][1], s["openings"].most_common(1)[0][0]) if s["openings"] else (0, "")
    open_concentration = top_open_count / n if n else 0

    # full-assistant duplicate rate
    dup_full = sum(c for c in s["asst_full_hash"].values() if c > 1)
    dup_full_pct = dup_full / n if n else 0

    rows.append({
        "source": src,
        "n": n,
        "L_med": L_med,
        "L_p10": L_p10,
        "L_p90": L_p90,
        "L_max": L_max,
        "L_narrow": round(narrow, 3),
        "top_open_pct": round(open_concentration * 100, 1),
        "dup_full_pct": round(dup_full_pct * 100, 1),
        "apt_fab_pct": round(s["apt_fabricated"] / max(1, s["apt_in_asst"]) * 100, 1),
        "apt_fab_n": s["apt_fabricated"],
        "dom_fab_pct": round(s["dom_fabricated"] / max(1, s["dom_in_asst"]) * 100, 1),
        "dom_fab_n": s["dom_fabricated"],
        "cve_fab_pct": round(s["cve_fabricated"] / max(1, s["cve_in_asst"]) * 100, 1),
        "cve_fab_n": s["cve_fabricated"],
        "hash_fab_pct": round(s["hash_fabricated"] / max(1, s["hash_in_asst"]) * 100, 1),
        "hash_fab_n": s["hash_fabricated"],
        "hedge_pct": round(s["has_hedge"] / n * 100, 1),
        "refusal_pct": round(s["is_refusal"] / n * 100, 1),
        "empty_pct": round(s["asst_empty"] / n * 100, 1),
        "tiny_pct": round(s["asst_tiny"] / n * 100, 1),
        "top_open_snippet": top_open[:80].replace("\n", " ⏎ "),
        "fab_apt_examples": s["fab_apt_examples"],
        "fab_dom_examples": s["fab_dom_examples"],
        "fab_cve_examples": s["fab_cve_examples"],
    })

rows.sort(key=lambda r: -r["n"])

# === Print main table ===
print("=" * 130)
print("PER-SOURCE AUDIT — v3.2 cleaned data")
print("=" * 130)
print(f"{'source':<22}{'n':>7}{'Lmed':>6}{'narr':>6}{'open%':>7}{'dup%':>6}{'aptF%':>7}{'domF%':>7}{'cveF%':>7}{'hashF%':>8}{'hedge%':>8}{'refus%':>8}{'tiny%':>7}")
print("-" * 130)
for r in rows:
    print(
        f"{r['source']:<22}"
        f"{r['n']:>7}"
        f"{r['L_med']:>6}"
        f"{r['L_narrow']:>6.2f}"
        f"{r['top_open_pct']:>7.1f}"
        f"{r['dup_full_pct']:>6.1f}"
        f"{r['apt_fab_pct']:>7.1f}"
        f"{r['dom_fab_pct']:>7.1f}"
        f"{r['cve_fab_pct']:>7.1f}"
        f"{r['hash_fab_pct']:>8.1f}"
        f"{r['hedge_pct']:>8.1f}"
        f"{r['refusal_pct']:>8.1f}"
        f"{r['tiny_pct']:>7.1f}"
    )

print("\nLegend:")
print("  Lmed     = median assistant length (chars)")
print("  narr     = (p90-p10)/median. <0.25 = suspiciously narrow length distribution (truncation artifact)")
print("  open%    = single 200-char opening prefix as % of records (template concentration)")
print("  dup%     = % records whose full assistant text duplicates another in same source")
print("  aptF%    = of records mentioning APT in asst, % where APT is not in user input")
print("  domF%    = of records with defanged domain in asst, % where domain is not in user input")
print("  cveF%    = of records mentioning CVE in asst, % where CVE is not in user input")
print("  hashF%   = of records with hash in asst, % where hash is not in user input")
print("  hedge%   = % records containing the v3.1 'Multi-phase / Unclassified' hedge pattern")
print("  refus%   = % records that look like a refusal/uncertainty pattern")
print("  tiny%    = % records with assistant <100 chars (low-signal)")

# === Heuristic flag scoring ===
print("\n" + "=" * 130)
print("RECOMMENDED DROP CANDIDATES (heuristic flags)")
print("=" * 130)

flagged = []
for r in rows:
    flags = []
    if r["L_narrow"] < 0.20 and r["n"] >= 100:
        flags.append(f"truncated-length (narr={r['L_narrow']:.2f})")
    if r["top_open_pct"] > 50 and r["n"] >= 50:
        flags.append(f"template-heavy ({r['top_open_pct']:.0f}% open)")
    if r["dup_full_pct"] > 30 and r["n"] >= 50:
        flags.append(f"dup-heavy ({r['dup_full_pct']:.0f}% dup)")
    if r["apt_fab_pct"] > 50 and r["apt_fab_n"] >= 5:
        flags.append(f"apt-fab ({r['apt_fab_pct']:.0f}%, n={r['apt_fab_n']})")
    if r["dom_fab_pct"] > 50 and r["dom_fab_n"] >= 5:
        flags.append(f"dom-fab ({r['dom_fab_pct']:.0f}%, n={r['dom_fab_n']})")
    if r["cve_fab_pct"] > 50 and r["cve_fab_n"] >= 5 and r["source"] != "synthetic_uncertainty":
        flags.append(f"cve-fab ({r['cve_fab_pct']:.0f}%, n={r['cve_fab_n']})")
    if r["hash_fab_pct"] > 30 and r["hash_fab_n"] >= 5:
        flags.append(f"hash-fab ({r['hash_fab_pct']:.0f}%, n={r['hash_fab_n']})")
    if r["hedge_pct"] > 40 and r["n"] >= 100:
        flags.append(f"over-hedge ({r['hedge_pct']:.0f}%)")
    if r["tiny_pct"] > 30 and r["n"] >= 100:
        flags.append(f"tiny-asst ({r['tiny_pct']:.0f}%)")

    if flags:
        flagged.append((r["source"], r["n"], flags))

if not flagged:
    print("(no sources flagged)")
else:
    for src, n, flags in sorted(flagged, key=lambda x: -x[1]):
        print(f"\n  {src} (n={n:,})")
        for f in flags:
            print(f"    - {f}")

# === Detailed look at top offenders ===
print("\n" + "=" * 130)
print("EXAMPLES from flagged sources")
print("=" * 130)
flagged_set = {f[0] for f in flagged}
for r in rows:
    if r["source"] not in flagged_set:
        continue
    print(f"\n--- {r['source']} (n={r['n']:,}) ---")
    print(f"  top opening ({r['top_open_pct']:.0f}% of records): {r['top_open_snippet']!r}")
    if r["fab_apt_examples"]:
        ex = r["fab_apt_examples"][0]
        print(f"  apt-fab example: fab={ex['fab']}")
        print(f"    user[:150]: {ex['u']!r}")
        print(f"    asst[:250]: {ex['a']!r}")
    if r["fab_dom_examples"]:
        ex = r["fab_dom_examples"][0]
        print(f"  dom-fab example: fab={ex['fab']}")
        print(f"    user[:150]: {ex['u']!r}")
        print(f"    asst[:250]: {ex['a']!r}")
    if r["fab_cve_examples"]:
        ex = r["fab_cve_examples"][0]
        print(f"  cve-fab example: fab={ex['fab']}")
        print(f"    user[:150]: {ex['u']!r}")
        print(f"    asst[:250]: {ex['a']!r}")

# === Write JSON for later reference ===
slim_rows = [{k: v for k, v in r.items() if not k.startswith("fab_")} for r in rows]
with open(OUT_JSON, "w") as f:
    json.dump({"total": total, "sources": slim_rows, "flagged": [{"source": s, "n": n, "flags": fl} for s, n, fl in flagged]}, f, indent=2)
print(f"\nwrote {OUT_JSON}")
