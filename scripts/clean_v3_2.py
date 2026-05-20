"""
Build v3.2 dataset from v3 cleaned data.

Drops three sources poisoning the model:
  - telegram      (3,282) — 100% OPSEC boilerplate, fabricates vxunderground attribution
  - misp_galaxy   (3,651) — 100% emit actor-lift template that caused SpaceX regression
  - hf_cyber_v1 <think>   — degenerate <think>-tag CoT outputs (224 records)

Stratified 85/7.5/7.5 split per source, then oversamples synthetic_uncertainty 3x
in train only, then removes train/valid/test user-message leakage.

Input : data/02_processed/v3_0_cleaned.jsonl
Output: data/02_processed/v3_2_cleaned.jsonl
        data/03_splits_v3.2/{train,valid,test}.jsonl
"""
import json
import hashlib
import random
from collections import Counter, defaultdict
from pathlib import Path

IN_PATH   = Path("/home/maximuz/osint-project/data/02_processed/v3_0_cleaned.jsonl")
OUT_PATH  = Path("/home/maximuz/osint-project/data/02_processed/v3_2_cleaned.jsonl")
SPLIT_DIR = Path("/home/maximuz/osint-project/data/03_splits_v3.2")

DROP_SOURCES = {"telegram", "misp_galaxy"}

# Drop hf_cyber_v1 records whose assistant has a <think> CoT block —
# Llama 3.2 3B can't reproduce that format and falls into repetition loops.
def has_think(rec):
    if rec["source"] != "hf_cyber_v1":
        return False
    for m in rec["messages"]:
        if m["role"] == "assistant" and "<think>" in m["content"].lower():
            return True
    return False

OVERSAMPLE_SOURCE = "synthetic_uncertainty"
OVERSAMPLE_X      = 3

random.seed(42)
SPLIT_DIR.mkdir(parents=True, exist_ok=True)

def user_key(rec):
    u = next(m["content"] for m in rec["messages"] if m["role"] == "user")
    return hashlib.sha1(u.strip().lower().encode()).hexdigest()

# === Load + filter ===
with open(IN_PATH) as f:
    raw = [json.loads(l) for l in f]

kept           = []
dropped_source = Counter()
dropped_think  = 0

for r in raw:
    if r["source"] in DROP_SOURCES:
        dropped_source[r["source"]] += 1
        continue
    if has_think(r):
        dropped_think += 1
        continue
    kept.append(r)

print(f"=== v3.2 cleaning ===")
print(f"input  : {len(raw):,}")
print(f"dropped (entire source):")
for s, n in dropped_source.most_common():
    print(f"  {n:>6,}  {s}")
print(f"dropped (hf_cyber_v1 <think>): {dropped_think:,}")
print(f"kept   : {len(kept):,}")

# === Write canonical cleaned file ===
with open(OUT_PATH, "w") as f:
    for r in kept:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"\nwrote {OUT_PATH}")

# === Stratified 85/7.5/7.5 split per source ===
by_src = defaultdict(list)
for r in kept:
    by_src[r["source"]].append(r)

train, valid, test = [], [], []
for s, recs in by_src.items():
    random.shuffle(recs)
    n = len(recs)
    n_train = int(n * 0.85)
    n_valid = int(n * 0.075)
    train.extend(recs[:n_train])
    valid.extend(recs[n_train:n_train + n_valid])
    test.extend(recs[n_train + n_valid:])

print(f"\n=== stratified split (pre-oversample, pre-leakcheck) ===")
print(f"  train {len(train):,}  valid {len(valid):,}  test {len(test):,}")

# === Oversample synthetic_uncertainty 3x in train only ===
honesty = [r for r in train if r["source"] == OVERSAMPLE_SOURCE]
rest    = [r for r in train if r["source"] != OVERSAMPLE_SOURCE]
train   = rest + honesty * OVERSAMPLE_X
random.shuffle(train)

print(f"\n=== oversample ===")
print(f"  {OVERSAMPLE_SOURCE}: {len(honesty)} -> {len(honesty)*OVERSAMPLE_X}  ({OVERSAMPLE_X}x)")
print(f"  train total: {len(train):,}")
print(f"  honesty proportion: {len(honesty)*OVERSAMPLE_X/len(train)*100:.2f}%")

# === Remove train/valid/test leakage on user message ===
train_keys = {user_key(r) for r in train}
valid_pre  = len(valid)
test_pre   = len(test)
valid = [r for r in valid if user_key(r) not in train_keys]
test  = [r for r in test  if user_key(r) not in train_keys]

valid_keys = {user_key(r) for r in valid}
test_pre2  = len(test)
test = [r for r in test if user_key(r) not in valid_keys]

print(f"\n=== leak removal ===")
print(f"  valid: {valid_pre:,} -> {len(valid):,}  (-{valid_pre-len(valid)} train leaks)")
print(f"  test : {test_pre:,} -> {len(test):,}  (-{test_pre-test_pre2} train leaks, -{test_pre2-len(test)} valid leaks)")

# === Write splits ===
def dump(recs, name):
    path = SPLIT_DIR / f"{name}.jsonl"
    with open(path, "w") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    mb = path.stat().st_size / 1024**2
    return mb

print(f"\n=== final splits ===")
for name, recs in [("train", train), ("valid", valid), ("test", test)]:
    mb = dump(recs, name)
    print(f"  {name:<6} {len(recs):>6,}  {mb:6.1f} MB  -> {SPLIT_DIR}/{name}.jsonl")

# === Final source distribution (train) ===
print(f"\n=== train source distribution ===")
src_train = Counter(r["source"] for r in train)
for s, n in src_train.most_common():
    print(f"  {n:>6,}  {s}")
