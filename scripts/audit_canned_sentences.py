import json
import re
import sys
from collections import defaultdict, Counter

CLEANED = sys.argv[1] if len(sys.argv) > 1 else "data/02_processed/v3_4_cleaned.jsonl"


def sentences(text):
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    out = []
    for p in parts:
        p = p.strip()
        if len(p) >= 40 and not p.endswith(":"):
            out.append(re.sub(r"\s+", " ", p))
    return out


def main():
    per_source = defaultdict(list)
    for line in open(CLEANED, encoding="utf-8"):
        r = json.loads(line)
        per_source[r["source"]].append(r["messages"][-1]["content"])

    print(f"{'source':24} {'n':>6} {'top_sentence_share':>18}  top canned sentence")
    print("-" * 110)
    for src, assts in sorted(per_source.items()):
        n = len(assts)
        sc = Counter()
        for a in assts:
            for s in set(sentences(a)):
                sc[s] += 1
        if not sc:
            continue
        top, cnt = sc.most_common(1)[0]
        share = cnt / n
        flag = "  <-- CANNED" if share > 0.30 else ""
        print(f"{src:24} {n:>6} {share:>17.2f}{flag}  {top[:64]}")


if __name__ == "__main__":
    main()
