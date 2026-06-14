"""
Build v3 dataset: cut garbage sources, filter over-hedge templates, dedupe,
strip hallucinated-attribution leaks, then stratified 85/7.5/7.5 split.

Input : data/02_processed/v2_0_cleaned.jsonl
Output: data/02_processed/v3_0_cleaned.jsonl
        data/03_splits/{train,valid,test}.jsonl  (overwritten)
"""
import json, os, random, hashlib
from collections import Counter, defaultdict

IN_PATH  = os.path.expanduser("~/osint-project/data/02_processed/v2_0_cleaned.jsonl")
OUT_PATH = os.path.expanduser("~/osint-project/data/02_processed/v3_0_cleaned.jsonl")
SPLIT_DIR = os.path.expanduser("~/osint-project/data/03_splits")

# Sources removed entirely (audit findings):
#   hf_fenrir       54% Conti hallucination, 16.6% of dataset
#   hf_loghub       98.8% identical boilerplate on benign Apache log lines
#   hf_cti          93% pure refusal templates
#   hf_hackernews   86% duplicated, off-topic news forced into OSINT format
#   bleepingcomputer 90% over-hedging, n=110
#   mandiant_blog   40% Conti hallucination, n=20
#   sans_isc        n=4
#   virustotal      10-word URL dumps, n=43
DROP_SOURCES = {
    "hf_fenrir", "hf_loghub", "hf_cti", "hf_hackernews",
    "bleepingcomputer", "mandiant_blog", "sans_isc", "virustotal",
}

# For these sources, drop records whose assistant matches a refusal template.
FILTER_RULES = {
    "cve": ["Multi-phase / Unclassified", "Unclassified — review CVE"],
    "otx": ["No machine-parseable IOCs", "Not explicitly named"],
}


def get_msg(rec, role):
    for m in rec["messages"]:
        if m["role"] == role:
            return m["content"]
    return ""


def main():
    random.seed(42)

    kept_by_src = Counter()
    dropped_source = Counter()
    dropped_filter = Counter()
    dropped_dup = Counter()
    dropped_conti = Counter()

    seen_pairs = set()
    kept = []

    with open(IN_PATH) as f:
        for line in f:
            r = json.loads(line)
            src = r["source"]

            if src in DROP_SOURCES:
                dropped_source[src] += 1
                continue

            asst = get_msg(r, "assistant")
            user = get_msg(r, "user")

            if any(p in asst for p in FILTER_RULES.get(src, [])):
                dropped_filter[src] += 1
                continue

            # Hallucination safety net: assistant invents "Conti" not in user input
            if "Conti" in asst and "Conti" not in user:
                dropped_conti[src] += 1
                continue

            # Dedupe on (user, assistant) pair
            h = hashlib.md5((user + "||" + asst).encode()).hexdigest()
            if h in seen_pairs:
                dropped_dup[src] += 1
                continue
            seen_pairs.add(h)

            kept.append(r)
            kept_by_src[src] += 1

    print(f"\n=== v3 cleaning summary ===")
    print(f"Kept: {len(kept):,} records")
    print(f"\nDropped by entire-source rule: {sum(dropped_source.values()):,}")
    for s, c in dropped_source.most_common():
        print(f"  {c:>6}  {s}")
    print(f"\nDropped by per-source filter (over-hedge templates): {sum(dropped_filter.values()):,}")
    for s, c in dropped_filter.most_common():
        print(f"  {c:>6}  {s}  ({100*c/(c+kept_by_src[s]):.1f}% of source)")
    print(f"\nDropped by Conti-hallucination safety net: {sum(dropped_conti.values()):,}")
    for s, c in dropped_conti.most_common():
        print(f"  {c:>6}  {s}")
    print(f"\nDropped exact (user,asst) duplicates: {sum(dropped_dup.values()):,}")
    for s, c in dropped_dup.most_common():
        print(f"  {c:>6}  {s}")

    print(f"\n=== final source distribution ===")
    total = len(kept)
    for s, c in kept_by_src.most_common():
        print(f"  {c:>6}  ({100*c/total:5.2f}%)  {s}")

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        for r in kept:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\nWrote {OUT_PATH}")

    # Stratified split: 85 / 7.5 / 7.5 per source
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

    random.shuffle(train); random.shuffle(valid); random.shuffle(test)

    os.makedirs(SPLIT_DIR, exist_ok=True)
    for name, split in [("train", train), ("valid", valid), ("test", test)]:
        path = f"{SPLIT_DIR}/{name}.jsonl"
        with open(path, "w") as f:
            for r in split:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        mb = os.path.getsize(path) / 1024**2
        pct = 100 * len(split) / total
        print(f"  {name:<6} {len(split):>6,} ({pct:5.2f}%)  {mb:6.1f} MB  -> {path}")


if __name__ == "__main__":
    main()
