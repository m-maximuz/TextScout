"""
Fix script for 3 sources that failed in phase 2:
  1. Atomic Red Team — use raw CDN instead of GitHub API
  2. arXiv cs.CR     — proper rate limiting
  3. MISP extra      — additional malware clusters (banker, stealer, rat, backdoor)
"""
import requests, json, os, re, time, hashlib, yaml
from xml.etree import ElementTree as ET

RAW = os.path.expanduser("~/osint-project/data/01_raw")

def make_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_existing(filepath):
    seen = set()
    if not os.path.exists(filepath):
        return seen
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                seen.add(make_hash(json.loads(line.strip())['text']))
            except Exception:
                pass
    return seen

def save(filepath, entry, seen):
    h = make_hash(entry['text'])
    if h in seen:
        return 0
    seen.add(h)
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    return 1

def get(url, headers=None, retries=4, sleep=5):
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 200:
                return r
            if r.status_code == 404:
                return None  # resource doesn't exist, no point retrying
            if r.status_code == 429:
                print(f"\n  [!] 429 rate limit, waiting 30s...")
                time.sleep(30)
            else:
                print(f"\n  [!] HTTP {r.status_code}, attempt {attempt+1}/{retries}")
                time.sleep(sleep)
        except Exception as e:
            print(f"\n  [!] {e}, attempt {attempt+1}/{retries}")
            time.sleep(sleep)
    return None

# ============================================================
# 1. Atomic Red Team — via raw CDN (no API rate limit)
# ============================================================
def fix_atomic_red_team():
    print("\n[*] Atomic Red Team (raw CDN — no API limit)...")
    path = f"{RAW}/atomic_red_team.jsonl"
    seen = load_existing(path)
    count = 0

    BASE = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"

    # Fetch index YAML — large file, gives all technique IDs
    print("  Fetching technique index...")
    r = get(f"{BASE}/Indexes/index.yaml")
    if not r:
        print("  [!] Could not fetch index")
        return 0

    # Extract all T\d{4} keys from the YAML
    tech_ids = sorted(set(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', r.text)))
    print(f"  Found {len(tech_ids)} technique IDs in index")

    for i, tech_id in enumerate(tech_ids):
        yaml_url = f"{BASE}/{tech_id}/{tech_id}.yaml"
        r = get(yaml_url)
        if not r:
            continue

        try:
            data = yaml.safe_load(r.text)
        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        display_name     = data.get('display_name', tech_id)
        attack_technique = data.get('attack_technique', tech_id)
        atomic_tests     = data.get('atomic_tests', [])

        for test in atomic_tests:
            test_name = (test.get('name') or '').strip()
            test_desc = (test.get('description') or '').strip()
            platforms = test.get('supported_platforms', [])
            executor  = (test.get('executor') or {}).get('name', '')

            if len(test_desc) < 30:
                continue

            parts = [
                f"ATT&CK Technique: {display_name} [{attack_technique}]",
                f"Test Name: {test_name}",
                f"Supported Platforms: {', '.join(platforms)}",
                f"\nProcedure Description:\n{test_desc}",
            ]
            if executor:
                parts.append(f"Execution Method: {executor}")

            input_args = test.get('input_arguments', {})
            if input_args:
                arg_lines = [f"  {k}: {v.get('description','')}"
                             for k, v in list(input_args.items())[:4]
                             if v.get('description')]
                if arg_lines:
                    parts.append("Parameters:\n" + '\n'.join(arg_lines))

            count += save(path, {
                'text':         '\n'.join(parts),
                'technique_id': attack_technique,
                'source':       'atomic_red_team',
                'date':         ''
            }, seen)

        if (i + 1) % 100 == 0:
            print(f"  → {i+1}/{len(tech_ids)} techniques, {count} records", end='\r')

        time.sleep(0.15)  # Polite CDN usage

    print(f"\n[+] Atomic Red Team: {count} records saved")
    return count

# ============================================================
# 2. arXiv cs.CR — proper rate limiting
# ============================================================
def fix_arxiv():
    print("\n[*] arXiv cs.CR (10s delay between batches)...")
    path = f"{RAW}/arxiv_security.jsonl"
    seen = load_existing(path)
    count = 0

    relevant_keywords = [
        'malware', 'ransomware', 'vulnerability', 'exploit', 'phishing',
        'intrusion', 'penetration', 'threat', 'adversar', 'social engineering',
        'botnet', 'credential', 'obfuscation', 'evasion', 'attribution',
        'threat intelligence', 'osint', 'anomaly detection', 'cyber',
        'attack', 'forensic', 'privacy', 'authentication',
    ]

    target     = 5000
    batch_size = 50   # smaller batches
    start      = 0
    ns         = {'atom': 'http://www.w3.org/2005/Atom'}
    fail_count = 0

    while count < target:
        url = (
            f"https://export.arxiv.org/api/query?"
            f"search_query=cat:cs.CR"
            f"&start={start}&max_results={batch_size}"
            f"&sortBy=submittedDate&sortOrder=descending"
        )
        r = get(url, retries=5, sleep=15)
        if not r:
            fail_count += 1
            if fail_count >= 3:
                print(f"\n  [!] Too many failures, stopping")
                break
            time.sleep(30)
            continue

        fail_count = 0

        try:
            root    = ET.fromstring(r.content)
            entries = root.findall('atom:entry', ns)
        except Exception as e:
            print(f"\n  [!] XML parse error: {e}")
            break

        if not entries:
            break

        batch_saved = 0
        for entry in entries:
            title_el   = entry.find('atom:title', ns)
            summary_el = entry.find('atom:summary', ns)
            pub_el     = entry.find('atom:published', ns)

            if title_el is None or summary_el is None:
                continue

            title     = title_el.text.strip().replace('\n', ' ')
            summary   = summary_el.text.strip()
            published = pub_el.text.strip() if pub_el is not None else ''

            combined = (title + ' ' + summary).lower()
            if not any(kw in combined for kw in relevant_keywords):
                continue

            summary_clean = re.sub(r'\s+', ' ', summary).strip()
            if len(summary_clean) < 100:
                continue

            batch_saved += save(path, {
                'text':   f"{title}\n\n{summary_clean}",
                'source': 'arxiv_security',
                'date':   published
            }, seen)

        count += batch_saved
        start += batch_size
        print(f"  → Scanned {start} papers, saved {count} relevant", end='\r')

        if len(entries) < batch_size:
            break

        time.sleep(10)  # arXiv rate limit — 10s between requests

    print(f"\n[+] arXiv cs.CR: {count} records saved")
    return count

# ============================================================
# 3. MISP Extra Clusters
# ============================================================
def fix_misp_extra():
    print("\n[*] MISP Galaxy — additional malware clusters...")
    path = f"{RAW}/misp_galaxy.jsonl"
    seen = load_existing(path)
    count = 0

    extra_clusters = [
        ('banker',   'malware_banker'),
        ('stealer',  'malware_stealer'),
        ('rat',      'malware_rat'),
        ('backdoor', 'malware_backdoor'),
    ]

    for cluster_name, cluster_type in extra_clusters:
        url = f"https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{cluster_name}.json"
        r = get(url)
        if not r:
            print(f"  [!] {cluster_name}.json not found, skipping")
            continue

        values = r.json().get('values', [])
        print(f"  → {cluster_name}: {len(values)} entries")
        cluster_count = 0

        for entry in values:
            name = entry.get('value', '').strip()
            desc = entry.get('description', '').strip()
            if not desc or len(desc) < 30:
                continue

            meta      = entry.get('meta', {})
            synonyms  = meta.get('synonyms', [])
            refs      = meta.get('refs', [])

            parts = [f"{name}: {desc}"]
            if synonyms:
                parts.append(f"Also known as: {', '.join(synonyms[:6])}")
            if refs:
                parts.append(f"References: {', '.join(str(r) for r in refs[:3])}")

            n = save(path, {
                'text':         '\n'.join(parts),
                'name':         name,
                'cluster_type': cluster_type,
                'source':       'misp_galaxy',
                'date':         ''
            }, seen)
            count += n
            cluster_count += n

        print(f"     → Saved {cluster_count} new records from {cluster_name}")
        time.sleep(1)

    print(f"[+] MISP Extra: {count} new records saved")
    return count

# ============================================================
# Run
# ============================================================
if __name__ == "__main__":
    print("=" * 55)
    print("Phase 2 Fix — Atomic Red Team + arXiv + MISP extra")
    print("=" * 55)

    counts = {}
    counts['Atomic Red Team'] = fix_atomic_red_team()
    counts['arXiv cs.CR']     = fix_arxiv()
    counts['MISP Extra']      = fix_misp_extra()

    print("\n" + "=" * 55)
    total = sum(counts.values())
    for k, v in counts.items():
        print(f"  {'✓' if v > 0 else '✗'} {k:<25} {v:>6} records")
    print(f"  {'Total':<25} {total:>6} records")
    print("=" * 55)

    # Final count
    grand = sum(
        sum(1 for _ in open(f"{RAW}/{f}"))
        for f in os.listdir(RAW) if f.endswith('.jsonl')
    )
    print(f"\n  Total in data/01_raw/: {grand:,} records")
