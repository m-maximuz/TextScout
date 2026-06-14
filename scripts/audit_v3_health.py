import json, os, re
from collections import Counter, defaultdict

D = os.path.expanduser("~/osint-project/data/03_splits_v3.4")
def load(n): return [json.loads(l) for l in open(os.path.join(D, n+".jsonl"), encoding="utf-8")]
train, valid, test = load("train"), load("valid"), load("test")

def sys_(r):  return r["messages"][0]["content"]
def usr(r):   return r["messages"][1]["content"]
def asst(r):  return r["messages"][-1]["content"]
def src(r):   return r.get("source", "?")

def refang(s):
    return (s.replace("[.]", ".").replace("[:]", ":")
             .replace("hxxps", "https").replace("hxxp", "http").replace("(.)", "."))

ENT = {
    "cve":    re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.I),
    "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "ipv4":   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "hash":   re.compile(r"\b[a-fA-F0-9]{32,64}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|br|top|xyz|info|biz|co|uk|de|shop|online|work|cc|tv|me)\b", re.I),
}
def ents(t):
    t = refang(t); out = set()
    for k, p in ENT.items():
        for m in p.findall(t): out.add((k, m.lower()))
    return out

print("="*70); print("1. STRUCTURE"); print("="*70)
bad_struct = 0
for split,nm in [(train,"train"),(valid,"valid"),(test,"test")]:
    for r in split:
        ms = r["messages"]
        roles = [m["role"] for m in ms]
        if roles[:1]!=["system"] or "user" not in roles or ms[-1]["role"]!="assistant" \
           or not usr(r).strip() or not asst(r).strip():
            bad_struct += 1
print(f"train/valid/test sizes: {len(train)}/{len(valid)}/{len(test)}")
print(f"malformed records: {bad_struct}")
sysset = Counter(sys_(r) for r in train+valid+test)
print(f"distinct system prompts: {len(sysset)} (want 1)")

print("\n"+"="*70); print("2. LEAKAGE (train vs valid/test)"); print("="*70)
eval_u = {usr(r) for r in valid+test}
eval_a = {asst(r) for r in valid+test}
u_leak = sum(1 for r in train if usr(r) in eval_u)
a_leak = sum(1 for r in train if asst(r) in eval_a)
print(f"train user-msgs also in valid/test: {u_leak}")
print(f"train assistant-msgs also in valid/test: {a_leak}")
# exact full-duplicate records inside train
keys = Counter((usr(r),asst(r)) for r in train)
print(f"exact-duplicate (user,assistant) pairs in train: {sum(c-1 for c in keys.values() if c>1)}")

print("\n"+"="*70); print("3. FABRICATION / GROUNDING  (assistant entities NOT in user input)"); print("="*70)
print("  high % = model is taught to invent indicators. refusals excluded.")
REF = re.compile(r"no (?:authoritative|record|data|profile|matching)|won'?t fabricate|no record found|not indexed|no att&ck", re.I)
per = defaultdict(lambda:[0,0,0])  # records_with_ents, total_ents, fabricated_ents
worst = []
for r in train:
    if REF.search(asst(r)): continue
    ai, ui = ents(asst(r)), ents(usr(r))
    if not ai: continue
    fab = ai - ui
    per[src(r)][0]+=1; per[src(r)][1]+=len(ai); per[src(r)][2]+=len(fab)
    if fab: worst.append((len(fab),src(r),sorted(fab)[:4],usr(r)[:60],asst(r)[:60]))
print(f"{'source':16s}{'recs':>6}{'ents':>7}{'fab':>6}{'fab%':>7}")
tot=[0,0]
for s,(rc,te,fe) in sorted(per.items(), key=lambda x:-(x[1][2]/max(x[1][1],1))):
    tot[0]+=te; tot[1]+=fe
    print(f"{s:16s}{rc:>6}{te:>7}{fe:>6}{(fe/max(te,1)*100):>6.1f}%")
print(f"{'OVERALL':16s}{'':>6}{tot[0]:>7}{tot[1]:>6}{tot[1]/max(tot[0],1)*100:>6.1f}%")

print("\n"+"="*70); print("4. CANNED / BOILERPLATE  (sentences repeated across many records)"); print("="*70)
sent = Counter()
for r in train:
    for s in re.split(r"(?<=[.\n])\s+", asst(r)):
        s=s.strip()
        if len(s)>25: sent[s]+=1
print("top repeated assistant sentences:")
for s,c in sent.most_common(8):
    print(f"  {c:>5}x  {s[:80]}")

print("\n"+"="*70); print("5. KNOWN BUG: truncated multi-part ccTLD domains"); print("="*70)
TRUNC = re.compile(r"\b([a-z0-9.-]+\.(?:com|co|net|org|gov|edu)\.(?:br|uk|au|in|za|jp|kr|cn|ru|mx|ar|tr|id|nz|sg|hk|tw|ua|pl|nl))\b", re.I)
trunc=0
for r in train:
    u=refang(usr(r)); a=refang(asst(r))
    for dom in set(TRUNC.findall(u)):
        if dom not in a and dom.rsplit(".",1)[0] in a: trunc+=1
print(f"records truncating a ccTLD domain in output: {trunc} (want 0)")

print("\n"+"="*70); print("6. HONESTY SIGNAL"); print("="*70)
refs = [r for r in train if REF.search(asst(r))]
print(f"refusal-style records in train: {len(refs)}  ({len(refs)/len(train)*100:.1f}% of train)")
print("  by source:", dict(Counter(src(r) for r in refs)))
print("  by input kind:", dict(Counter(("cve" if "[CVE Record]" in usr(r) else "actor" if "Group lookup" in usr(r) else "other") for r in refs)))

print("\nWORST fabrication examples (non-refusal):")
for n,s,fab,u,a in sorted(worst,reverse=True)[:6]:
    print(f"  [{s}] +{n} fabricated {fab}\n    U:{u}\n    A:{a}")
