"""
Build v3.3 dataset from v3.2 cleaned data.

Drops three additional sources that the v3.3 audit identified as poisoning
the model's honesty / structure on free-text scenarios:

  - hf_cyber_v1   (1,637) — 87% APT-fab, 97% domain-fab, 97% CVE-fab in
                            assistant relative to user input. Length is
                            clipped to ~2,500 chars, which trains the
                            model to pad with repetition (test record 4
                            regression).
  - cve           (1,137) — 100% of records put a CVE-ID in the assistant
                            that is not present in user input (description
                            -> fabricated CVE-ID). Trains the
                            "make up an authoritative identifier from a
                            description" pattern. CVE coverage is preserved
                            by cisa_kev (CVE in user+asst) and ghsa.
  - mitre_attack  (2,167) — top 5 boilerplate assistants cover 45% of
                            records (356x / 213x / 210x / 126x / 66x
                            identical text). Same failure shape as
                            misp_galaxy (which v3.2 dropped) — the model
                            learns "MITRE-style input -> emit boilerplate,
                            ignore user content."

Stratified 85/7.5/7.5 split per source, 3x synthetic_uncertainty oversample
in train only, train/valid/test leak removal on user-message hash. Same
shape as clean_v3_2.py.

Input : data/02_processed/v3_2_cleaned.jsonl
Output: data/02_processed/v3_3_cleaned.jsonl
        data/03_splits_v3.3/{train,valid,test}.jsonl
"""
import json
import hashlib
import random
from collections import Counter, defaultdict
from pathlib import Path

IN_PATH   = Path("/home/maximuz/osint-project/data/02_processed/v3_2_cleaned.jsonl")
OUT_PATH  = Path("/home/maximuz/osint-project/data/02_processed/v3_3_cleaned.jsonl")
SPLIT_DIR = Path("/home/maximuz/osint-project/data/03_splits_v3.3")

DROP_SOURCES = {"hf_cyber_v1", "cve", "mitre_attack"}

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

for r in raw:
    if r["source"] in DROP_SOURCES:
        dropped_source[r["source"]] += 1
        continue
    kept.append(r)

print(f"=== v3.3 cleaning ===")
print(f"input  : {len(raw):,}")
print(f"dropped (entire source):")
for s, n in dropped_source.most_common():
    print(f"  {n:>6,}  {s}")
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
