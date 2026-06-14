import json
import os
import re
import random
from collections import defaultdict, Counter

BASE = os.path.expanduser("~/osint-project/data/02_processed/v3_4_cleaned.jsonl")
GROUNDED = os.path.expanduser("~/osint-project/data/04_curation_v2_4/grounded_records.jsonl")
PROBE = os.path.expanduser("~/osint-project/data/05_eval_probes/honesty_probe.jsonl")
OUTDIR = os.path.expanduser("~/osint-project/data/03_splits_v3.4")
GHSA_CAP = 3000
SMOKE = ["lyrebird", "stoneraven", "cve-9999-987654"]
RATIOS = (0.85, 0.075, 0.075)

# single canonical system prompt — MUST match the eval (ai-test.ipynb) and the deployed app.
# evidence-gated: reason from the record, refuse on empty lookups, never judge by the name.
CANON_SYSTEM = (
    "You are an expert cybersecurity analyst specializing in Text OSINT and threat "
    "intelligence for red team operations. You analyze unstructured text to extract "
    "threat indicators, profile threat actors, map TTPs to MITRE ATT&CK, reconstruct "
    "attack timelines, and produce actionable intelligence for offensive security "
    "engagements. Work only from the record provided: extract and analyze what is present, "
    "and when a lookup is empty or no record is given, say so plainly instead of inventing "
    "details. Judge by the evidence in the input, not by whether a name looks familiar."
)

random.seed(13)


def held_out_terms():
    actors, cves = set(), set()
    for line in open(PROBE, encoding="utf-8"):
        r = json.loads(line)
        if r["category"] in ("real_actor", "fake_actor"):
            actors.add(r["identifier"])
        if r["category"] in ("real_cve", "fake_cve"):
            cves.add(r["identifier"].upper())
    actors |= {"Sandworm Team", "GOLD SOUTHFIELD", "Equation", "APT32", "Magic Hound", "menuPass"}
    actor_pats = [re.compile(rf"\b{re.escape(a)}\b", re.I) for a in actors]
    cve_pats = [re.compile(re.escape(c), re.I) for c in cves]
    smoke_pats = [re.compile(re.escape(s), re.I) for s in SMOKE]
    return actor_pats + cve_pats + smoke_pats, actors, cves



TRUNC_TLD = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|co|net|org|gov|edu)\.(?:br|uk|au|in|za|jp|kr|cn|ru|mx|ar|tr|id|nz|sg|hk|tw|ua|pl|nl|il|ph|vn|th))\b", re.I)
def _refang(s):
    return s.replace("[.]", ".").replace("hxxps", "https").replace("hxxp", "http")
def has_truncated_domain(r):
    # IOC mutation: the output lists a domain that is a real multi-part ccTLD domain with its
    # final label dropped (.com.br -> .com). The full domain may still survive in a URL line,
    # so compare against domains explicitly listed under "Domains:" rather than substring presence.
    u = _refang(" ".join(m["content"] for m in r["messages"][:-1]))
    a = _refang(r["messages"][-1]["content"])
    truth = set(d.lower() for d in TRUNC_TLD.findall(u + " " + a))
    listed = set(d.lower() for d in re.findall(r"(?mi)^\s*-\s*([a-z0-9.-]+\.[a-z]{2,})\s*$", a))
    listed |= set(d.lower() for d in re.findall(r"Domains?:\s*-?\s*([a-z0-9.-]+\.[a-z]{2,})", a, re.I))
    for full in truth:
        if full.rsplit(".", 1)[0] in listed and full not in listed:
            return True
    return False

def text_of(r):
    return " ".join(m["content"] for m in r["messages"])


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    records = [json.loads(l) for l in open(BASE, encoding="utf-8")]
    if os.path.exists(GROUNDED):
        records += [json.loads(l) for l in open(GROUNDED, encoding="utf-8")]

    pats, actors, cves = held_out_terms()
    kept, leaked, truncated = [], 0, 0
    for r in records:
        if r["source"] in ("real_actor", "real_cve"):
            kept.append(r)  # grounded set already excludes probe IDs by construction
            continue
        t = text_of(r)
        if any(p.search(t) for p in pats):
            leaked += 1
            continue
        if has_truncated_domain(r):
            truncated += 1
            continue
        kept.append(r)
    print(f"[*] Dropped {leaked} leaked, {truncated} IOC-truncated records")

    for r in kept:
        if r["messages"][0]["role"] == "system":
            r["messages"][0]["content"] = CANON_SYSTEM
        else:
            r["messages"].insert(0, {"role": "system", "content": CANON_SYSTEM})

    by_src = defaultdict(list)
    for r in kept:
        by_src[r["source"]].append(r)
    if len(by_src.get("ghsa", [])) > GHSA_CAP:
        random.shuffle(by_src["ghsa"])
        by_src["ghsa"] = by_src["ghsa"][:GHSA_CAP]
        print(f"[*] Capped ghsa to {GHSA_CAP}")

    train, valid, test = [], [], []
    for src, recs in by_src.items():
        random.shuffle(recs)
        n = len(recs)
        n_tr = int(n * RATIOS[0])
        n_va = int(n * (RATIOS[0] + RATIOS[1]))
        train += recs[:n_tr]
        valid += recs[n_tr:n_va]
        test += recs[n_va:]

    eval_user_msgs = {r["messages"][1]["content"] for r in valid + test}
    train = [r for r in train if r["messages"][1]["content"] not in eval_user_msgs]

    for name, split in [("train", train), ("valid", valid), ("test", test)]:
        random.shuffle(split)
        with open(os.path.join(OUTDIR, f"{name}.jsonl"), "w", encoding="utf-8") as f:
            for r in split:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\nsplits -> {OUTDIR}")
    print(f"  train {len(train)} / valid {len(valid)} / test {len(test)}")
    print("\ntrain composition:")
    for s, n in Counter(r["source"] for r in train).most_common():
        print(f"  {n:>5} ({n/len(train)*100:4.1f}%)  {s}")

    # verify no leak in any split
    bad = 0
    for split in (train, valid, test):
        for r in split:
            if r["source"] in ("real_actor", "real_cve"):
                continue
            if any(p.search(text_of(r)) for p in pats):
                bad += 1
    print(f"\n[verify] held-out identifiers found in non-grounded split records: {bad} (want 0)")


if __name__ == "__main__":
    main()
