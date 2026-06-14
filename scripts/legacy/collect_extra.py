import requests, json, os, time, hashlib

RAW = os.path.expanduser("~/osint-project/data/raw")
ABUSECH_KEY  = os.environ.get("ABUSECH_KEY", "")
VT_KEY       = os.environ.get("VT_KEY", "")

def make_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_existing(filepath):
    seen = set()
    if not os.path.exists(filepath):
        return seen
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                r = json.loads(line.strip())
                seen.add(make_hash(r['text']))
            except (json.JSONDecodeError, KeyError):
                pass
    return seen

def count_records(filepath):
    if not os.path.exists(filepath):
        return 0
    with open(filepath, 'r', encoding='utf-8') as f:
        return sum(1 for _ in f)

def save(filepath, entry, seen):
    h = make_hash(entry['text'])
    if h in seen:
        return 0
    seen.add(h)
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    return 1

def get_json(url, headers=None, retries=5, sleep=7):
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 200 and r.text.strip():
                return r.json()
            elif r.status_code == 429:
                print(f"\n  [!] Rate limit รอ 60 วิ...")
                time.sleep(60)
            else:
                print(f"\n  [!] HTTP {r.status_code} attempt {attempt+1}/{retries}")
                time.sleep(sleep)
        except requests.exceptions.RequestException as e:
            print(f"\n  [!] Network error: {e} attempt {attempt+1}/{retries}")
            time.sleep(sleep)
    return None

# ---- ThreatFox ----
def collect_threatfox():
    print("\n[*] ThreatFox (abuse.ch)...")
    path = f"{RAW}/threatfox.jsonl"
    seen = load_existing(path)
    count = 0
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": ABUSECH_KEY},
            json={"query": "get_iocs", "days": 7},
            timeout=30
        )
        response = r.json()
        if response.get('query_status') != 'ok':
            print(f"  [!] ThreatFox status: {response.get('query_status')}")
            return 0
        for ioc in response.get('data', []):
            if not isinstance(ioc, dict):
                continue
            malware       = ioc.get('malware', '')
            ioc_value     = ioc.get('ioc', '')
            ioc_type      = ioc.get('ioc_type', '')
            threat_desc   = ioc.get('threat_type_desc', '')
            tags          = ', '.join(ioc.get('tags') or [])
            text = f"{malware} {ioc_type}: {ioc_value}. {threat_desc}"
            if tags:
                text += f" tags: {tags}"
            text = text.strip()
            if len(text) > 20:
                count += save(path, {
                    "text":     text,
                    "malware":  malware,
                    "ioc_type": ioc_type,
                    "source":   "threatfox",
                    "date":     ioc.get('first_seen', '')
                }, seen)
    except Exception as e:
        print(f"  [!] ThreatFox error: {e}")
    print(f"[+] ThreatFox เพิ่ม {count} records ใหม่")
    return count

# ---- CISA KEV ----
def collect_cisa_kev():
    print("\n[*] CISA Known Exploited Vulnerabilities...")
    path = f"{RAW}/cisa_kev.jsonl"
    seen = load_existing(path)
    count = 0

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = get_json(url)
    if not data:
        print("  [!] ดึง CISA KEV ไม่ได้")
        return 0

    for vuln in data.get('vulnerabilities', []):
        cve_id      = vuln.get('cveID', '')
        product     = vuln.get('product', '')
        vendor      = vuln.get('vendorProject', '')
        name        = vuln.get('vulnerabilityName', '')
        description = vuln.get('shortDescription', '')
        action      = vuln.get('requiredAction', '')

        text = f"{cve_id} {vendor} {product}: {name}. {description}"
        if action:
            text += f" Required action: {action}"
        text = text.strip()

        if len(text) > 30:
            count += save(path, {
                "text":    text,
                "cve_id":  cve_id,
                "vendor":  vendor,
                "product": product,
                "source":  "cisa_kev",
                "date":    vuln.get('dateAdded', '')
            }, seen)

    print(f"[+] CISA KEV เพิ่ม {count} records ใหม่")
    return count

# ---- VirusTotal ----
def collect_virustotal():
    print("\n[*] VirusTotal comments...")
    path = f"{RAW}/virustotal.jsonl"
    seen = load_existing(path)
    count = 0
    headers = {"x-apikey": VT_KEY}
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/comments",
            headers=headers,
            params={"limit": 40},
            timeout=30
        )
        data = r.json()
        for item in data.get('data', []):
            if not isinstance(item, dict):
                continue
            attrs = item.get('attributes', {})
            # ดึง text จาก html หรือ text field
            text = attrs.get('text', '') or attrs.get('html', '')
            # ลบ HTML tags อย่างง่าย
            import re
            text = re.sub(r'<[^>]+>', '', text).strip()
            if len(text) > 30:
                count += save(path, {
                    "text":   text,
                    "source": "virustotal_comments",
                    "date":   str(attrs.get('date', ''))
                }, seen)
            time.sleep(0.8)  # 4 requests/min limit
    except Exception as e:
        print(f"  [!] VirusTotal error: {e}")
    print(f"[+] VirusTotal เพิ่ม {count} records ใหม่")
    return count

# ---- Summary ----
def print_summary():
    print("\n" + "="*60)
    print("📊 สรุปข้อมูลใหม่")
    print("="*60)
    total = 0
    files = ['threatfox.jsonl', 'cisa_kev.jsonl', 'virustotal.jsonl']
    for filename in files:
        path = f"{RAW}/{filename}"
        if os.path.exists(path):
            lines = count_records(path)
            size  = os.path.getsize(path) // 1024
            print(f"  {filename:<28} {lines:>6} records  ({size} KB)")
            total += lines
        else:
            print(f"  {filename:<28} ยังไม่มีไฟล์")
    print("-"*60)
    print(f"  {'รวมใหม่':<28} {total:>6} records")
    print("="*60)

if __name__ == "__main__":
    os.makedirs(RAW, exist_ok=True)
    print("🚀 เริ่มเก็บข้อมูลเพิ่มเติม...")
    collect_threatfox()
    collect_cisa_kev()
    collect_virustotal()
    print("\n✅ เสร็จแล้ว!")
    print_summary()
