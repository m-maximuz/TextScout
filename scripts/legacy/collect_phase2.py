import requests, json, os, re, time, hashlib, csv, io, yaml
from xml.etree import ElementTree as ET

RAW          = os.path.expanduser("~/osint-project/data/01_raw")
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')

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

def get(url, headers=None, retries=3, sleep=5):
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 200:
                return r
            if r.status_code in (429, 403):
                print(f"\n  [!] Rate limit ({r.status_code}), waiting 60s...")
                time.sleep(60)
            else:
                print(f"\n  [!] HTTP {r.status_code}, attempt {attempt+1}/{retries}")
                time.sleep(sleep)
        except Exception as e:
            print(f"\n  [!] {e}, attempt {attempt+1}/{retries}")
            time.sleep(sleep)
    return None

def clean_html(text):
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r'&#(\d+);',            lambda m: chr(int(m.group(1))),    text)
    text = re.sub(r'&[a-zA-Z]+;', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()

# ============================================================
# 1. MISP Galaxy
# ============================================================
def collect_misp_galaxy():
    print("\n[*] MISP Galaxy (threat actors, malware, tools)...")
    path = f"{RAW}/misp_galaxy.jsonl"
    seen = load_existing(path)
    count = 0

    clusters = [
        ('threat-actor',  'threat_actor'),
        ('malware',       'malware'),
        ('tool',          'attack_tool'),
        ('ransomware',    'ransomware'),
        ('malpedia',      'malware_detailed'),
    ]

    for cluster_name, cluster_type in clusters:
        url = f"https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{cluster_name}.json"
        r = get(url)
        if not r:
            print(f"  [!] Skipping {cluster_name}")
            continue

        values = r.json().get('values', [])
        print(f"  → {cluster_name}: {len(values)} entries")

        for entry in values:
            name = entry.get('value', '').strip()
            desc = entry.get('description', '').strip()
            if not desc or len(desc) < 30:
                continue

            meta      = entry.get('meta', {})
            synonyms  = meta.get('synonyms', [])
            country   = meta.get('country') or meta.get('cfr-suspected-state-sponsor', '')
            targets   = meta.get('cfr-target-category', [])
            refs      = meta.get('refs', [])

            parts = [f"{name}: {desc}"]
            if synonyms:
                parts.append(f"Also known as: {', '.join(synonyms[:8])}")
            if country:
                parts.append(f"Country/Origin: {country}")
            if targets:
                parts.append(f"Target sectors: {', '.join(str(t) for t in targets[:5])}")
            if refs:
                parts.append(f"References: {', '.join(str(r) for r in refs[:3])}")

            count += save(path, {
                'text':         '\n'.join(parts),
                'name':         name,
                'cluster_type': cluster_type,
                'source':       'misp_galaxy',
                'date':         ''
            }, seen)

        time.sleep(1)

    print(f"[+] MISP Galaxy: {count} records saved")
    return count

# ============================================================
# 2. GitHub Security Advisories (GHSA)
# ============================================================
def collect_ghsa():
    print("\n[*] GitHub Security Advisories (GHSA)...")
    path = f"{RAW}/ghsa.jsonl"
    seen = load_existing(path)
    count = 0

    headers = {'Accept': 'application/vnd.github+json'}
    if GITHUB_TOKEN:
        headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'
        print("  Using GitHub token — 5000 req/hr")
    else:
        print("  No GITHUB_TOKEN set — limited to 60 req/hr (slower but works)")

    url = "https://api.github.com/advisories?per_page=100&type=reviewed"
    page = 1

    while url:
        r = get(url, headers=headers)
        if not r:
            break

        advisories = r.json()
        if not isinstance(advisories, list) or len(advisories) == 0:
            break

        for adv in advisories:
            ghsa_id   = adv.get('ghsa_id', '')
            cve_id    = adv.get('cve_id', '')
            severity  = (adv.get('severity') or 'unknown').upper()
            summary   = (adv.get('summary') or '').strip()
            desc      = (adv.get('description') or '').strip()
            vulns     = adv.get('vulnerabilities', [])
            published = adv.get('published_at', '')

            # Clean markdown code blocks — keep prose, remove code
            desc_clean = re.sub(r'```[\s\S]*?```', '[code omitted]', desc)
            desc_clean = re.sub(r'`[^`\n]+`', lambda m: m.group(0).strip('`'), desc_clean)
            desc_clean = re.sub(r'\n{3,}', '\n\n', desc_clean).strip()

            parts = []
            if summary:
                parts.append(f"Advisory: {summary}")
            if cve_id:
                parts.append(f"CVE: {cve_id}")
            parts.append(f"GHSA: {ghsa_id}  |  Severity: {severity}")

            if vulns:
                pkg = vulns[0].get('package', {})
                pkg_name  = pkg.get('name', '')
                ecosystem = pkg.get('ecosystem', '')
                affected  = vulns[0].get('vulnerable_version_range', '')
                if pkg_name:
                    parts.append(f"Affected Package: {pkg_name} ({ecosystem})"
                                 + (f"  versions {affected}" if affected else ''))

            if desc_clean and len(desc_clean) > 50:
                parts.append(f"\nDetails:\n{desc_clean[:2000]}")

            text = '\n'.join(parts)
            if len(text) < 60:
                continue

            count += save(path, {
                'text':     text,
                'ghsa_id':  ghsa_id,
                'cve_id':   cve_id,
                'severity': severity,
                'source':   'ghsa',
                'date':     published
            }, seen)

        # Parse next-page URL from Link header
        link = r.headers.get('Link', '')
        match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = match.group(1) if match else None

        print(f"  → Page {page}, {count} records saved", end='\r')
        page += 1
        time.sleep(0.5 if GITHUB_TOKEN else 2)

    print(f"\n[+] GHSA: {count} records saved")
    return count

# ============================================================
# 3. Exploit-DB
# ============================================================
def collect_exploitdb():
    print("\n[*] Exploit-DB (GitLab CSV mirror)...")
    path = f"{RAW}/exploitdb.jsonl"
    seen = load_existing(path)
    count = 0

    r = get("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv")
    if not r:
        print("  [!] Could not fetch Exploit-DB CSV")
        return 0

    type_labels = {
        'remote':  'Remote exploit — executable from the network without local access',
        'local':   'Local exploit — requires existing foothold (privilege escalation path)',
        'dos':     'Denial of Service — crashes or degrades the target service',
        'webapps': 'Web application exploit — targets web stack (PHP, ASP, SQL, JS, etc.)',
    }

    total = 0
    for row in csv.DictReader(io.StringIO(r.text)):
        total += 1
        if row.get('verified', '0').strip() != '1':
            continue

        desc     = row.get('description', '').strip()
        etype    = row.get('type', '').strip().lower()
        platform = row.get('platform', '').strip()
        author   = row.get('author', '').strip()
        codes    = row.get('codes', '').strip()
        date     = row.get('date_published', '').strip()
        tags     = row.get('tags', '').strip()

        if len(desc) < 10:
            continue

        parts = [f"Exploit: {desc}"]
        parts.append(f"Type: {type_labels.get(etype, etype)}")
        if platform:
            parts.append(f"Platform: {platform}")

        cves = [c.strip() for c in re.split(r'[;,]', codes) if 'CVE-' in c.upper()]
        if cves:
            parts.append(f"CVE References: {', '.join(cves)}")

        if tags:
            parts.append(f"Tags: {tags}")
        if author:
            parts.append(f"Author: {author}")
        if date:
            parts.append(f"Published: {date}")

        count += save(path, {
            'text':         '\n'.join(parts),
            'exploit_type': etype,
            'platform':     platform,
            'source':       'exploitdb',
            'date':         date
        }, seen)

    print(f"  CSV rows: {total:,} | Verified & saved: {count:,}")
    print(f"[+] Exploit-DB: {count} records saved")
    return count

# ============================================================
# 4. Atomic Red Team
# ============================================================
def collect_atomic_red_team():
    print("\n[*] Atomic Red Team (redcanaryco/atomic-red-team)...")
    path = f"{RAW}/atomic_red_team.jsonl"
    seen = load_existing(path)
    count = 0

    # Get technique list from GitHub API directory listing
    gh_headers = {'Accept': 'application/vnd.github+json'}
    if GITHUB_TOKEN:
        gh_headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'

    r = get("https://api.github.com/repos/redcanaryco/atomic-red-team/contents/atomics",
            headers=gh_headers)
    if not r:
        print("  [!] Could not list atomics directory")
        return 0

    entries  = r.json()
    tech_ids = sorted({e['name'] for e in entries
                       if e['type'] == 'dir' and re.match(r'T\d{4}', e['name'])})
    print(f"  Found {len(tech_ids)} technique folders")

    for i, tech_id in enumerate(tech_ids):
        yaml_url = (
            f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team"
            f"/master/atomics/{tech_id}/{tech_id}.yaml"
        )
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
            executor  = test.get('executor', {})
            exec_name = executor.get('name', '')

            if len(test_desc) < 30:
                continue

            parts = [
                f"ATT&CK Technique: {display_name} [{attack_technique}]",
                f"Test Name: {test_name}",
                f"Supported Platforms: {', '.join(platforms)}",
                f"\nProcedure Description:\n{test_desc}",
            ]
            if exec_name:
                parts.append(f"Execution Method: {exec_name}")

            # Add input args context if meaningful
            input_args = test.get('input_arguments', {})
            if input_args:
                arg_lines = []
                for arg_name, arg_info in list(input_args.items())[:4]:
                    arg_desc = arg_info.get('description', '')
                    if arg_desc:
                        arg_lines.append(f"  {arg_name}: {arg_desc}")
                if arg_lines:
                    parts.append("Parameters:\n" + '\n'.join(arg_lines))

            count += save(path, {
                'text':         '\n'.join(parts),
                'technique_id': attack_technique,
                'source':       'atomic_red_team',
                'date':         ''
            }, seen)

        if (i + 1) % 50 == 0:
            print(f"  → {i+1}/{len(tech_ids)} techniques processed, {count} records", end='\r')

        time.sleep(0.2)

    print(f"\n[+] Atomic Red Team: {count} records saved")
    return count

# ============================================================
# 5. Mandiant / Google Threat Intelligence Blog
# ============================================================
def collect_mandiant():
    print("\n[*] Mandiant / Google Threat Intelligence Blog (RSS)...")
    path = f"{RAW}/mandiant_blog.jsonl"
    seen = load_existing(path)
    count = 0

    feeds = [
        "https://www.mandiant.com/resources/blog/rss.xml",
        "https://cloud.google.com/blog/topics/threat-intelligence/rss.xml",
    ]

    for feed_url in feeds:
        r = get(feed_url, headers={'User-Agent': 'Mozilla/5.0'})
        if not r:
            continue
        try:
            root  = ET.fromstring(r.content)
            items = root.findall('.//item')
            print(f"  → {feed_url.split('/')[2]}: {len(items)} items")

            for item in items:
                title = (item.findtext('title') or '').strip()
                desc  = item.findtext('description') or ''
                date  = (item.findtext('pubDate')
                         or item.findtext('{http://purl.org/dc/elements/1.1/}date', '')
                         or '')

                desc_clean = clean_html(desc)
                if len(desc_clean) < 100:
                    continue

                text = f"{title}\n\n{desc_clean}"
                count += save(path, {
                    'text':   text,
                    'source': 'mandiant_blog',
                    'date':   date
                }, seen)
        except Exception as e:
            print(f"  [!] Parse error: {e}")

    print(f"[+] Mandiant Blog: {count} records saved")
    return count

# ============================================================
# 6. SANS Internet Storm Center
# ============================================================
def collect_sans_isc():
    print("\n[*] SANS Internet Storm Center (ISC Diaries)...")
    path = f"{RAW}/sans_isc.jsonl"
    seen = load_existing(path)
    count = 0

    r = get("https://isc.sans.edu/rssfeed.xml")
    if not r:
        print("  [!] Could not fetch SANS ISC RSS")
        return 0

    try:
        root  = ET.fromstring(r.content)
        items = root.findall('.//item')
        print(f"  → {len(items)} diary entries found")

        for item in items:
            title = (item.findtext('title') or '').strip()
            desc  = item.findtext('description') or ''
            date  = item.findtext('pubDate') or ''

            # Skip podcast stubs — no real content
            if 'Stormcast' in title:
                continue

            desc_clean = clean_html(desc)
            if len(desc_clean) < 80:
                continue

            text = f"{title}\n\n{desc_clean}"
            count += save(path, {
                'text':   text,
                'source': 'sans_isc',
                'date':   date
            }, seen)
    except Exception as e:
        print(f"  [!] Parse error: {e}")

    print(f"[+] SANS ISC: {count} records saved")
    return count

# ============================================================
# 7. arXiv cs.CR — Security Research Papers
# ============================================================
def collect_arxiv():
    print("\n[*] arXiv cs.CR (security research papers)...")
    path = f"{RAW}/arxiv_security.jsonl"
    seen = load_existing(path)
    count = 0

    relevant_keywords = [
        'malware', 'ransomware', 'vulnerability', 'exploit', 'phishing',
        'intrusion', 'penetration', 'threat', 'adversar', 'social engineering',
        'botnet', 'credential', 'obfuscation', 'evasion', 'attribution',
        'threat intelligence', 'osint', 'anomaly detection', 'cyber',
        'attack', 'authentication', 'cryptography', 'privacy', 'forensic',
    ]

    target     = 5000
    batch_size = 100
    start      = 0
    ns         = {'atom': 'http://www.w3.org/2005/Atom'}

    while count < target:
        url = (
            f"https://export.arxiv.org/api/query?"
            f"search_query=cat:cs.CR"
            f"&start={start}&max_results={batch_size}"
            f"&sortBy=submittedDate&sortOrder=descending"
        )
        r = get(url)
        if not r:
            break

        try:
            root    = ET.fromstring(r.content)
            entries = root.findall('atom:entry', ns)
        except Exception as e:
            print(f"  [!] XML parse error: {e}")
            break

        if not entries:
            break

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

            text = f"{title}\n\n{summary_clean}"
            count += save(path, {
                'text':   text,
                'source': 'arxiv_security',
                'date':   published
            }, seen)

        start += batch_size
        print(f"  → Scanned {start} papers, saved {count} relevant records", end='\r')

        if len(entries) < batch_size:
            break

        time.sleep(3)  # arXiv rate limit requirement

    print(f"\n[+] arXiv cs.CR: {count} records saved")
    return count

# ============================================================
# Summary
# ============================================================
def print_summary(counts):
    print("\n" + "=" * 55)
    print("Phase 2 Collection Complete")
    print("=" * 55)
    total = 0
    for source, n in counts.items():
        status = "✓" if n > 0 else "✗"
        print(f"  {status} {source:<28} {n:>6} records")
        total += n
    print("-" * 55)
    print(f"  Total new records: {total:,}")
    print("=" * 55)

    # Show overall dataset size
    raw_dir = os.path.expanduser("~/osint-project/data/01_raw")
    grand_total = 0
    for fname in os.listdir(raw_dir):
        if fname.endswith('.jsonl'):
            with open(f"{raw_dir}/{fname}") as f:
                grand_total += sum(1 for _ in f)
    print(f"\n  Total records in data/01_raw/: {grand_total:,}")

if __name__ == "__main__":
    os.makedirs(RAW, exist_ok=True)
    print("=" * 55)
    print("Phase 2 Data Collection")
    print("=" * 55)
    if GITHUB_TOKEN:
        print(f"GitHub token: set ({GITHUB_TOKEN[:8]}...)")
    else:
        print("GitHub token: not set (GHSA collection will be slow)")

    counts = {}
    counts['MISP Galaxy']     = collect_misp_galaxy()
    counts['GHSA']            = collect_ghsa()
    counts['Exploit-DB']      = collect_exploitdb()
    counts['Atomic Red Team'] = collect_atomic_red_team()
    counts['Mandiant Blog']   = collect_mandiant()
    counts['SANS ISC']        = collect_sans_isc()
    counts['arXiv cs.CR']     = collect_arxiv()

    print_summary(counts)
