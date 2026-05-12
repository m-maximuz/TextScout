"""
Exploratory Data Analysis for OSINT-AI Dataset
Run: python scripts/eda.py
Produces printed stats + saves charts to reports/eda/
"""
import json, os, re, collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

CLEANED = os.path.expanduser("~/osint-project/data/02_processed/v2_0_cleaned.jsonl")
OUT_DIR = os.path.expanduser("~/osint-project/reports/eda")
os.makedirs(OUT_DIR, exist_ok=True)

print("Loading dataset...")
records = []
with open(CLEANED) as f:
    for line in f:
        try:
            records.append(json.loads(line))
        except Exception:
            pass

total = len(records)
print(f"Total records: {total:,}\n")

# ============================================================
# 1. Source Distribution
# ============================================================
print("=" * 55)
print("1. SOURCE DISTRIBUTION")
print("=" * 55)

source_counts = collections.Counter(r.get("source", "unknown") for r in records)
for src, count in source_counts.most_common():
    bar  = "█" * int(count / total * 40)
    pct  = count / total * 100
    print(f"  {src:<30} {count:>6} ({pct:4.1f}%)  {bar}")

# Pie chart
fig, ax = plt.subplots(figsize=(10, 7))
labels  = [s for s, _ in source_counts.most_common()]
sizes   = [c for _, c in source_counts.most_common()]
colors  = plt.cm.tab20.colors
wedges, texts, autotexts = ax.pie(
    sizes, labels=labels, autopct=lambda p: f'{p:.1f}%' if p > 2 else '',
    colors=colors[:len(labels)], startangle=140
)
ax.set_title("Dataset Source Distribution", fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/source_distribution.png", dpi=150, bbox_inches='tight')
plt.close()
print(f"\n  Chart saved: {OUT_DIR}/source_distribution.png")

# ============================================================
# 2. Real vs AI-Generated
# ============================================================
print("\n" + "=" * 55)
print("2. REAL vs AI-GENERATED DATA")
print("=" * 55)

AI_GENERATED = {"hf_fenrir", "hf_cyber_v1"}
real_count = sum(1 for r in records if r.get("source") not in AI_GENERATED)
ai_count   = total - real_count
print(f"  Real data (human-written / API feeds) : {real_count:,} ({real_count/total*100:.1f}%)")
print(f"  AI-generated (synthetic Q&A)          : {ai_count:,}  ({ai_count/total*100:.1f}%)")

fig, ax = plt.subplots(figsize=(6, 4))
ax.bar(["Real / API Data", "AI-Generated Q&A"], [real_count, ai_count],
       color=["#2ecc71", "#e74c3c"], edgecolor='black')
ax.set_ylabel("Record Count")
ax.set_title("Real vs Synthetic Training Data", fontweight='bold')
for i, v in enumerate([real_count, ai_count]):
    ax.text(i, v + 200, f"{v:,}\n({v/total*100:.1f}%)", ha='center', fontsize=10)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/real_vs_synthetic.png", dpi=150)
plt.close()

# ============================================================
# 3. Text Length Distribution
# ============================================================
print("\n" + "=" * 55)
print("3. TEXT LENGTH DISTRIBUTION (user message)")
print("=" * 55)

lengths = []
for r in records:
    msgs = r.get("messages", [])
    user_msg = next((m["content"] for m in msgs if m["role"] == "user"), "")
    lengths.append(len(user_msg))

import statistics
print(f"  Min    : {min(lengths):,} chars")
print(f"  Max    : {max(lengths):,} chars")
print(f"  Mean   : {statistics.mean(lengths):,.0f} chars")
print(f"  Median : {statistics.median(lengths):,.0f} chars")
print(f"  Stdev  : {statistics.stdev(lengths):,.0f} chars")

buckets = {"<100": 0, "100–500": 0, "500–1000": 0, "1000–2000": 0, "2000–4096": 0, ">4096": 0}
for l in lengths:
    if   l < 100:    buckets["<100"] += 1
    elif l < 500:    buckets["100–500"] += 1
    elif l < 1000:   buckets["500–1000"] += 1
    elif l < 2000:   buckets["1000–2000"] += 1
    elif l <= 4096:  buckets["2000–4096"] += 1
    else:            buckets[">4096"] += 1

print("\n  Length bucket breakdown:")
for bucket, count in buckets.items():
    print(f"  {bucket:<12} {count:>6} ({count/total*100:.1f}%)")

fig, ax = plt.subplots(figsize=(8, 4))
ax.hist(lengths, bins=50, color='steelblue', edgecolor='black', alpha=0.7)
ax.axvline(statistics.median(lengths), color='red', linestyle='--', label=f'Median: {statistics.median(lengths):.0f}')
ax.set_xlabel("Text Length (characters)")
ax.set_ylabel("Number of Records")
ax.set_title("User Message Length Distribution", fontweight='bold')
ax.legend()
ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/text_length_distribution.png", dpi=150)
plt.close()

# ============================================================
# 4. IOC Coverage
# ============================================================
print("\n" + "=" * 55)
print("4. IOC COVERAGE")
print("=" * 55)

ioc_counts = {"has_CVE": 0, "has_IP": 0, "has_domain": 0, "has_hash": 0, "has_url": 0, "no_ioc": 0}

for r in records:
    msgs = r.get("messages", [])
    full_text = " ".join(m["content"] for m in msgs)
    has_any = False
    if re.search(r'CVE-\d{4}-\d+', full_text, re.IGNORECASE):
        ioc_counts["has_CVE"] += 1; has_any = True
    if re.search(r'\b\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\b', full_text):
        ioc_counts["has_IP"] += 1; has_any = True
    if re.search(r'\b[a-zA-Z0-9\-]+\[\.\][a-zA-Z]{2,10}\b', full_text):
        ioc_counts["has_domain"] += 1; has_any = True
    if re.search(r'\b[a-fA-F0-9]{32,64}\b', full_text):
        ioc_counts["has_hash"] += 1; has_any = True
    if re.search(r'hxxps?://', full_text):
        ioc_counts["has_url"] += 1; has_any = True
    if not has_any:
        ioc_counts["no_ioc"] += 1

for ioc_type, count in ioc_counts.items():
    print(f"  {ioc_type:<15} {count:>6} ({count/total*100:.1f}%)")

fig, ax = plt.subplots(figsize=(8, 4))
labels = [k.replace("has_", "") for k in list(ioc_counts.keys())]
values = list(ioc_counts.values())
colors = ['#3498db','#e67e22','#9b59b6','#1abc9c','#e74c3c','#95a5a6']
bars = ax.bar(labels, values, color=colors, edgecolor='black')
ax.set_ylabel("Records Containing IOC Type")
ax.set_title("IOC Type Coverage in Dataset", fontweight='bold')
for bar, val in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 100,
            f'{val:,}', ha='center', va='bottom', fontsize=9)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/ioc_coverage.png", dpi=150)
plt.close()

# ============================================================
# 5. MITRE ATT&CK Coverage
# ============================================================
print("\n" + "=" * 55)
print("5. MITRE ATT&CK TECHNIQUE COVERAGE")
print("=" * 55)

all_techniques = []
for r in records:
    msgs = r.get("messages", [])
    full_text = " ".join(m["content"] for m in msgs)
    techs = re.findall(r'T\d{4}(?:\.\d{3})?', full_text)
    all_techniques.extend(techs)

tech_counter = collections.Counter(all_techniques)
print(f"  Unique techniques referenced : {len(tech_counter):,}")
print(f"  Total technique mentions     : {sum(tech_counter.values()):,}")
print(f"\n  Top 15 most referenced techniques:")
for tech, count in tech_counter.most_common(15):
    print(f"    {tech}  ×{count}")

# ============================================================
# 6. Kill Chain Phase Distribution
# ============================================================
print("\n" + "=" * 55)
print("6. KILL CHAIN COVERAGE (from assistant responses)")
print("=" * 55)

kill_chain_keywords = {
    "Reconnaissance":        ['reconnaissance', 'recon', 'scanning', 'enumeration', 'osint'],
    "Initial Access":        ['initial access', 'phishing', 'spear phishing', 'watering hole'],
    "Execution":             ['code execution', 'shellcode', 'macro', 'script execution'],
    "Persistence":           ['persistence', 'backdoor', 'rootkit', 'scheduled task'],
    "Privilege Escalation":  ['privilege escalation', 'privesc', 'elevation of privilege'],
    "Credential Access":     ['credential', 'mimikatz', 'lsass', 'kerberoasting'],
    "Lateral Movement":      ['lateral movement', 'pass the hash', 'psexec', 'rdp'],
    "Command & Control":     ['command and control', 'c2', 'cobalt strike', 'beacon'],
    "Exfiltration":          ['exfiltration', 'data theft', 'exfiltrate'],
    "Impact":                ['ransomware', 'wiper', 'encrypt files', 'destruction'],
}

phase_counts = collections.defaultdict(int)
for r in records:
    msgs = r.get("messages", [])
    asst_text = next((m["content"].lower() for m in msgs if m["role"] == "assistant"), "")
    for phase, keywords in kill_chain_keywords.items():
        if any(kw in asst_text for kw in keywords):
            phase_counts[phase] += 1

print(f"  (Records can cover multiple phases)\n")
for phase, count in sorted(phase_counts.items(), key=lambda x: -x[1]):
    bar = "█" * int(count / total * 30)
    print(f"  {phase:<25} {count:>6} ({count/total*100:.1f}%)  {bar}")

fig, ax = plt.subplots(figsize=(10, 5))
phases = list(phase_counts.keys())
counts = [phase_counts[p] for p in phases]
sorted_pairs = sorted(zip(counts, phases), reverse=True)
counts, phases = zip(*sorted_pairs)
ax.barh(phases, counts, color='steelblue', edgecolor='black')
ax.set_xlabel("Number of Records")
ax.set_title("Kill Chain Phase Coverage", fontweight='bold')
for i, v in enumerate(counts):
    ax.text(v + 50, i, f'{v:,}', va='center', fontsize=9)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/kill_chain_coverage.png", dpi=150)
plt.close()

# ============================================================
# 7. Summary
# ============================================================
print("\n" + "=" * 55)
print("EDA SUMMARY")
print("=" * 55)
print(f"  Total training records        : {total:,}")
print(f"  Unique data sources           : {len(source_counts)}")
print(f"  Real vs synthetic ratio       : {real_count/total*100:.1f}% real")
print(f"  Avg text length (user msg)    : {statistics.mean(lengths):.0f} chars")
print(f"  Records with at least 1 IOC   : {total - ioc_counts['no_ioc']:,} ({(total-ioc_counts['no_ioc'])/total*100:.1f}%)")
print(f"  Unique ATT&CK techniques      : {len(tech_counter)}")
print(f"  Kill chain phases covered     : {len([p for p,c in phase_counts.items() if c > 0])}/10")
print(f"\n  All charts saved to: {OUT_DIR}/")
