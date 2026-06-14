import json
import re
import sys
from collections import Counter, defaultdict

CLEANED = sys.argv[1] if len(sys.argv) > 1 else "data/02_processed/v3_3_cleaned.jsonl"


def norm(text):
    t = text.lower()
    t = re.sub(r"cve-\d{4}-\d{3,7}", "<cve>", t)
    t = re.sub(r"t\d{4}(?:\.\d{3})?", "<ttp>", t)
    t = re.sub(r"ghsa-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", "<ghsa>", t)
    t = re.sub(r"\b[0-9a-f]{32,64}\b", "<hash>", t)
    t = re.sub(r"\b(?:\d{1,3}[.\[\]]+){3}\d{1,3}\b", "<ip>", t)
    t = re.sub(r"https?://\S+|hxxps?://\S+", "<url>", t)
    t = re.sub(r"\b[a-z0-9.-]+\[?\.\]?[a-z]{2,}\b", "<domain>", t)
    t = re.sub(r"\d+", "#", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def main():
    by_source = defaultdict(list)
    for line in open(CLEANED, encoding="utf-8"):
        r = json.loads(line)
        asst = r["messages"][-1]["content"]
        by_source[r["source"]].append(asst)

    rows = []
    for src, assts in by_source.items():
        n = len(assts)
        exact = Counter(assts)
        skel = Counter(norm(a) for a in assts)
        uniq_exact = len(exact) / n
        uniq_skel = len(skel) / n
        top_exact = exact.most_common(1)[0][1] / n
        top5_skel = sum(c for _, c in skel.most_common(5)) / n
        rows.append((src, n, uniq_exact, uniq_skel, top_exact, top5_skel, len(skel)))

    rows.sort(key=lambda r: r[3])
    print(f"{'source':24} {'n':>6} {'uniq_exact':>10} {'uniq_skel':>9} {'top1_exact':>10} {'top5_skel':>9} {'#skel':>6}")
    print("-" * 82)
    for src, n, ue, us, te, t5, ns in rows:
        flag = "  <-- TEMPLATED" if us < 0.5 or t5 > 0.4 else ""
        print(f"{src:24} {n:>6} {ue:>10.2f} {us:>9.2f} {te:>10.2f} {t5:>9.2f} {ns:>6}{flag}")

    print("\nLegend: uniq_skel = fraction of records with a unique entity-normalized skeleton.")
    print("Low uniq_skel or high top5_skel = many records share the same pattern (memorization risk).")


if __name__ == "__main__":
    main()
