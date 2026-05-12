"""
Split v2_0_cleaned.jsonl into train / valid / test
Output: data/03_splits/train.jsonl, valid.jsonl, test.jsonl
"""
import json, os, random

CLEANED = os.path.expanduser("~/osint-project/data/02_processed/v2_0_cleaned.jsonl")
OUT_DIR = os.path.expanduser("~/osint-project/data/03_splits")
os.makedirs(OUT_DIR, exist_ok=True)

TRAIN_RATIO = 0.90
VALID_RATIO = 0.05
TEST_RATIO  = 0.05

print("Loading cleaned dataset...")
with open(CLEANED) as f:
    records = [json.loads(l) for l in f]

total = len(records)
print(f"Total records: {total:,}")

random.seed(42)
random.shuffle(records)

train_end = int(total * TRAIN_RATIO)
valid_end = train_end + int(total * VALID_RATIO)

train = records[:train_end]
valid = records[train_end:valid_end]
test  = records[valid_end:]

print(f"  Train : {len(train):,} ({len(train)/total*100:.1f}%)")
print(f"  Valid : {len(valid):,} ({len(valid)/total*100:.1f}%)")
print(f"  Test  : {len(test):,}  ({len(test)/total*100:.1f}%)")

for name, split in [("train", train), ("valid", valid), ("test", test)]:
    path = f"{OUT_DIR}/{name}.jsonl"
    with open(path, "w") as f:
        for r in split:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    size_mb = os.path.getsize(path) / 1024**2
    print(f"  Saved {path}  ({size_mb:.1f} MB)")

print("\nDone. Upload the 3 files in data/03_splits/ to Kaggle as a dataset.")
