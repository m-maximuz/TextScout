"""v3.3 pre-flight check — pointed at data/03_splits_v3.3/.

Mirrors audit_v3_1.py exactly, plus an extra check that the v3.3 dropped
sources (hf_cyber_v1, cve, mitre_attack) are actually gone from all splits.
"""
import json
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path("/home/maximuz/osint-project/data/03_splits_v3.3")
SPLITS = ["train", "valid", "test"]
DROPPED_SOURCES = {"hf_cyber_v1", "cve", "mitre_attack"}

def load(split):
    with open(ROOT / f"{split}.jsonl") as f:
        return [json.loads(l) for l in f]

def key(rec):
    user = next(m["content"] for m in rec["messages"] if m["role"] == "user")
    return hashlib.sha1(user.strip().lower().encode()).hexdigest()

def asst_key(rec):
    asst = next(m["content"] for m in rec["messages"] if m["role"] == "assistant")
    return hashlib.sha1(asst.strip().lower().encode()).hexdigest()

print("=" * 60)
print("LOADING SPLITS")
print("=" * 60)
data = {s: load(s) for s in SPLITS}
for s, recs in data.items():
    print(f"  {s:6} {len(recs):,}")

print()
print("=" * 60)
print("CHECK 1: schema validity")
print("=" * 60)
bad_schema = 0
for split, recs in data.items():
    for i, r in enumerate(recs):
        if "messages" not in r or "source" not in r:
            bad_schema += 1
            continue
        roles = [m.get("role") for m in r["messages"]]
        if roles != ["system", "user", "assistant"]:
            bad_schema += 1
            if bad_schema <= 3:
                print(f"  BAD {split}[{i}] roles={roles}")
        for m in r["messages"]:
            if not isinstance(m.get("content"), str) or not m["content"].strip():
                bad_schema += 1
                if bad_schema <= 3:
                    print(f"  EMPTY content {split}[{i}] role={m.get('role')}")
print(f"  schema violations: {bad_schema}")

print()
print("=" * 60)
print("CHECK 2: dropped sources actually absent")
print("=" * 60)
for split, recs in data.items():
    src = Counter(r["source"] for r in recs)
    leaks = {s: src[s] for s in DROPPED_SOURCES if src[s] > 0}
    if leaks:
        print(f"  ✗ {split} contains dropped sources: {leaks}")
    else:
        print(f"  ✓ {split} clean of {sorted(DROPPED_SOURCES)}")

print()
print("=" * 60)
print("CHECK 3: system prompt consistency")
print("=" * 60)
sys_prompts = Counter()
for recs in data.values():
    for r in recs:
        sys_prompts[r["messages"][0]["content"]] += 1
print(f"  unique system prompts: {len(sys_prompts)}")
if len(sys_prompts) > 5:
    print(f"  WARN: more than 5 system prompts, may dilute training signal")
for sp, n in sys_prompts.most_common(3):
    print(f"  [{n:,}] {sp[:80]}...")

print()
print("=" * 60)
print("CHECK 4: train/valid/test leakage (by user message)")
print("=" * 60)
keys = {s: set(key(r) for r in data[s]) for s in SPLITS}
print(f"  train ∩ valid : {len(keys['train'] & keys['valid'])}")
print(f"  train ∩ test  : {len(keys['train'] & keys['test'])}")
print(f"  valid ∩ test  : {len(keys['valid'] & keys['test'])}")

print()
print("=" * 60)
print("CHECK 5: smoke-test honesty identifiers (must be absent)")
print("=" * 60)
refs = [
    "lyrebird",                 # APT-Lyrebird-77 fake actor smoke test
    "stoneraven",               # APT-Stoneraven-42 fake actor smoke test (added 2026-05-17)
    "cve-9999-987654",          # fake CVE smoke test
    "apt-phantom-91",           # earlier fake actor (caught leaking, swapped out)
]
for ref in refs:
    hits_per_split = {}
    for split, recs in data.items():
        hits_per_split[split] = sum(1 for r in recs if ref in json.dumps(r).lower())
    flag = "" if sum(hits_per_split.values()) == 0 else "  ← LEAK"
    print(f"  '{ref:30}' train={hits_per_split['train']} valid={hits_per_split['valid']} test={hits_per_split['test']}{flag}")

print()
print("=" * 60)
print("CHECK 6: identifiers known to be in train (accepted impurity)")
print("=" * 60)
known_in_train = [
    "airdrop-update",           # SpaceX scenario domain — in training
    "cs-watermark-987654321",   # cobalt strike scenario watermark — in training
    "139.59.226.78",            # cobalt strike scenario IP — in training
]
for ref in known_in_train:
    hits_per_split = {}
    for split, recs in data.items():
        hits_per_split[split] = sum(1 for r in recs if ref in json.dumps(r).lower())
    print(f"  '{ref:30}' train={hits_per_split['train']} valid={hits_per_split['valid']} test={hits_per_split['test']}")

print()
print("=" * 60)
print("CHECK 7: synthetic_uncertainty oversample sanity")
print("=" * 60)
for split, recs in data.items():
    syn = [r for r in recs if r["source"] == "synthetic_uncertainty"]
    unique_user = len(set(key(r) for r in syn))
    print(f"  {split:6} syn total={len(syn):,} unique user msgs={unique_user:,}")
syn_train = [r for r in data["train"] if r["source"] == "synthetic_uncertainty"]
if syn_train:
    unique = len(set(key(r) for r in syn_train))
    if len(syn_train) == unique * 3:
        print(f"  ✓ train syn is exactly 3× (expected from oversample)")
    else:
        print(f"  WARN: expected 3× duplication, got {len(syn_train)}/{unique} = {len(syn_train)/unique:.2f}×")
print(f"  honesty proportion in train: {len(syn_train)/len(data['train'])*100:.2f}%")

print()
print("=" * 60)
print("CHECK 8: assistant template duplication (templated-collapse risk)")
print("=" * 60)
asst_dupes = Counter()
for r in data["train"]:
    if r["source"] == "synthetic_uncertainty": continue
    asst_dupes[asst_key(r)] += 1
total_train_nonsyn = sum(1 for r in data["train"] if r["source"] != "synthetic_uncertainty")
dup_records = sum(c for _, c in asst_dupes.items() if c > 1)
print(f"  non-syn train records: {total_train_nonsyn:,}")
print(f"  records with duplicate assistant text: {dup_records:,} ({dup_records/total_train_nonsyn*100:.1f}%)")
asst_to_text = {}
for r in data["train"]:
    if r["source"] == "synthetic_uncertainty": continue
    h = asst_key(r)
    if h not in asst_to_text:
        asst_to_text[h] = next(m["content"] for m in r["messages"] if m["role"] == "assistant")
print(f"  top 5 most-duplicated assistant texts in train:")
for h, n in asst_dupes.most_common(5):
    print(f"    [{n:4}×] {asst_to_text[h][:90]!r}...")

print()
print("=" * 60)
print("CHECK 9: source distribution (train)")
print("=" * 60)
src_train = Counter(r["source"] for r in data["train"])
for src, n in src_train.most_common():
    print(f"  {n:>6,}  {src}")

print()
print("=" * 60)
print("CHECK 10: length distribution (train, char count, full conversation)")
print("=" * 60)
lens = []
for r in data["train"]:
    total = sum(len(m["content"]) for m in r["messages"])
    lens.append(total)
lens.sort()
print(f"  min={lens[0]:,}  p50={lens[len(lens)//2]:,}  p90={lens[int(len(lens)*0.9)]:,}  p99={lens[int(len(lens)*0.99)]:,}  max={lens[-1]:,}")
oversize = sum(1 for L in lens if L > 6000)
print(f"  records > 6000 chars (likely truncated by MAX_SEQ_LENGTH=1024 tokens): {oversize:,} ({oversize/len(lens)*100:.1f}%)")

print()
print("=" * 60)
print("CHECK 11: honesty subtype breakdown (train, after oversample)")
print("=" * 60)
syn = [r for r in data["train"] if r["source"] == "synthetic_uncertainty"]
def categorize(rec):
    user = next(m["content"] for m in rec["messages"] if m["role"]=="user").lower()
    if re.search(r"cve-\d{4}-\d", user): return "fake_cve"
    if re.search(r"apt-[a-z]|threat actor|profile.*(?:actor|group|apt)|attribute", user): return "fake_actor_named"
    if re.search(r"operation\s+\w+|campaign\s+\w+", user): return "fake_operation"
    if any(t in user for t in ["translate","recipe","weather","joke","poem"]): return "out_of_scope"
    if any(t in user for t in ["current","today","latest","real-time","right now"]): return "real_time"
    if any(t in user for t in ["hash","ioc","domain","ip"]) and len(user) < 100: return "minimal_input"
    return "other_or_short"
cats = Counter(categorize(r) for r in syn)
for c, n in cats.most_common():
    print(f"  {n:>5}  {c}")

print()
print("=" * 60)
print("VERDICT")
print("=" * 60)
issues = []
if bad_schema: issues.append(f"schema violations: {bad_schema}")
if len(keys['train'] & keys['valid']) > 0: issues.append(f"train/valid leak: {len(keys['train'] & keys['valid'])}")
if len(keys['train'] & keys['test']) > 0: issues.append(f"train/test leak: {len(keys['train'] & keys['test'])}")
if len(keys['valid'] & keys['test']) > 0: issues.append(f"valid/test leak: {len(keys['valid'] & keys['test'])}")

for split, recs in data.items():
    src = Counter(r["source"] for r in recs)
    for s in DROPPED_SOURCES:
        if src[s] > 0:
            issues.append(f"dropped source '{s}' still in {split}: {src[s]}")

for ref in ["lyrebird", "stoneraven", "cve-9999-987654", "apt-phantom-91"]:
    for split in SPLITS:
        n = sum(1 for r in data[split] if ref in json.dumps(r).lower())
        if n > 0:
            issues.append(f"smoke-test id '{ref}' in {split}: {n}")

if not issues:
    print("  ✓ NO BLOCKERS — safe to upload to Kaggle and retrain")
else:
    print("  ✗ ISSUES FOUND:")
    for i in issues: print(f"    - {i}")
