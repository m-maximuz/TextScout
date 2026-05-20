import json
import hashlib
import random
from pathlib import Path

SRC = Path("/home/maximuz/osint-project/data/03_splits")
DST = Path("/home/maximuz/osint-project/data/03_splits_v3.1")
OVERSAMPLE_SOURCE = "synthetic_uncertainty"
OVERSAMPLE_X = 3

DST.mkdir(parents=True, exist_ok=True)

def load(name):
    with open(SRC / f"{name}.jsonl") as f:
        return [json.loads(l) for l in f]

def user_key(rec):
    u = next(m["content"] for m in rec["messages"] if m["role"] == "user")
    return hashlib.sha1(u.strip().lower().encode()).hexdigest()

train = load("train")
valid = load("valid")
test  = load("test")

train_keys = {user_key(r) for r in train}
valid_clean = [r for r in valid if user_key(r) not in train_keys]
test_clean  = [r for r in test  if user_key(r) not in train_keys]

valid_keys = {user_key(r) for r in valid_clean}
test_clean = [r for r in test_clean if user_key(r) not in valid_keys]

honesty = [r for r in train if r["source"] == OVERSAMPLE_SOURCE]
rest    = [r for r in train if r["source"] != OVERSAMPLE_SOURCE]
new_train = rest + honesty * OVERSAMPLE_X

random.seed(42)
random.shuffle(new_train)

def dump(recs, name):
    with open(DST / f"{name}.jsonl", "w") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

dump(new_train,   "train")
dump(valid_clean, "valid")
dump(test_clean,  "test")

print(f"train  : {len(train):,} -> {len(new_train):,}  ({len(honesty)} honesty x{OVERSAMPLE_X})")
print(f"valid  : {len(valid):,} -> {len(valid_clean):,}  (-{len(valid)-len(valid_clean)} train leaks)")
print(f"test   : {len(test):,} -> {len(test_clean):,}  (-{len(test)-len(test_clean)} train+valid leaks)")
print(f"honesty proportion : {len(honesty)/len(train)*100:.2f}% -> {len(honesty)*OVERSAMPLE_X/len(new_train)*100:.2f}%")
print(f"output dir         : {DST}")
