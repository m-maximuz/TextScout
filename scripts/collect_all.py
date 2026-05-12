import requests, json, os, time, hashlib
from datetime import datetime, timezone, timedelta

RAW = os.path.expanduser("~/osint-project/data/raw")
ABUSECH_KEY = "1504b27b446c94e828c56a8932d9d8ca1d90ea1ac7f4a4dc"
OTX_KEY     = "421593bacfab3ea0b0e2647d3d9e9496223252514435947deb2ff6a43e1ae76b"
NVD_KEY     = "B8de124c-8edd-4f4a-89f9-336131ba17a4"

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

def get_json(url, headers=None, params=None, retries=5, sleep=7):
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=30)
            if r.status_code == 200 and r.text.strip():
                return r.json()
            elif r.status_code == 429:
                print(f"\n  [!] Rate limit รอ 60 วิ...")
                time.sleep(60)
            elif r.status_code == 403:
                print(f"\n  [!] 403 Forbidden รอ 60 วิ...")
                time.sleep(60)
            else:
                print(f"\n  [!] HTTP {r.status_code} attempt {attempt+1}/{retries} รอ {sleep} วิ...")
                time.sleep(sleep)
        except requests.exceptions.RequestException as e:
            print(f"\n  [!] Network error: {e} attempt {attempt+1}/{retries} รอ {sleep} วิ...")
            time.sleep(sleep)
    return None

def collect_abusech():
    print("\n[*] abuse.ch URLhaus...")
    path = f"{RAW}/abusech.jsonl"
    seen = load_existing(path)
    count = 0
    headers = {"Auth-Key": ABUSECH_KEY}
    data = get_json("https://urlhaus-api.abuse.ch/v1/urls/recent/", headers=headers)
    if not data:
        print("  [!] ดึง abuse.ch ไม่ได้ ข้ามไป")
        return 0
    for record in data.get('urls', []):
        text = f"{record.get('url','')} {record.get('threat','')}".strip()
        if text:
            count += save(path, {
                "text":   text,
                "threat": record.get("threat", ""),
                "source": "abuse.ch",
                "date":   record.get("date_added", "")
            }, seen)
    print(f"[+] abuse.ch เพิ่ม {count} records ใหม่")
    return count

def collect_cve(target=10000):
    print(f"\n[*] CVE NVD (เป้าหมาย {target} records ใหม่)...")
    path = f"{RAW}/cve.jsonl"
    seen = load_existing(path)
    existing = count_records(path)
    print(f"  มีอยู่แล้ว {existing} records")

    CHUNK_DAYS = 110
    count = 0
    fail_count = 0
    headers = {"apiKey": NVD_KEY} if "ใส่" not in NVD_KEY else {}
    chunk_end = datetime.now(timezone.utc)

    while count < target:
        chunk_start = chunk_end - timedelta(days=CHUNK_DAYS)
        start_str = chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000%2B00:00")
        end_str   = chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000%2B00:00")

        start_idx = 0
        while True:
            params = {
                "lastModStartDate": chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                "lastModEndDate":   chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                "resultsPerPage":   100,
                "startIndex":       start_idx
            }
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            data = get_json(base_url, headers=headers, params=params)
            if not data:
                fail_count += 1
                print(f"\n  [!] ดึงไม่ได้ ({fail_count}/3) รอ 30 วิ...")
                time.sleep(30)
                if fail_count >= 3:
                    print("  [!] ล้มเหลว 3 ครั้งติด หยุด CVE collector")
                    return count
                continue

            fail_count = 0
            vulns = data.get('vulnerabilities', [])
            if not vulns:
                break

            for item in vulns:
                cve  = item.get('cve', {})
                text = next((d['value'] for d in cve.get('descriptions', [])
                             if d['lang'] == 'en'), None)
                if text:
                    count += save(path, {
                        "text":   text,
                        "cve_id": cve.get('id', ''),
                        "source": "nvd_mitre",
                        "date":   cve.get('published', '')
                    }, seen)

            total_results = data.get('totalResults', 0)
            start_idx += 100
            print(f"  → ได้ {count}/{target} ใหม่ | chunk {start_str[:10]}~{end_str[:10]}", end='\r')

            if start_idx >= total_results:
                break
            time.sleep(7 if not headers else 1)

        chunk_end = chunk_start
        if chunk_end.year < 2010:
            print("\n  [+] ดึง CVE ครบช่วงเวลาแล้ว")
            break
        time.sleep(3)

    print(f"\n[+] CVE เพิ่ม {count} records ใหม่")
    return count

def collect_otx():
    print("\n[*] OTX AlienVault (ดูดทั้งหมด)...")
    path = f"{RAW}/otx.jsonl"
    seen = load_existing(path)
    count = 0
    empty_pages = 0
    headers = {"X-OTX-API-KEY": OTX_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=100"
    page = 1

    while url:
        data = get_json(url, headers=headers)
        if not data:
            print(f"\n  [!] OTX หยุดที่ page {page}")
            break

        results = data.get('results', [])
        if not results:
            empty_pages += 1
            if empty_pages >= 3:
                print("\n  [+] OTX หมดข้อมูลแล้ว")
                break
        else:
            empty_pages = 0
            for pulse in results:
                text = f"{pulse.get('name','')} {pulse.get('description','')}".strip()
                if text:
                    count += save(path, {
                        "text":   text,
                        "source": "otx_alienvault",
                        "date":   pulse.get('created', '')
                    }, seen)

        next_url = data.get('next')
        url = next_url if (next_url and next_url.startswith('http')) else None
        print(f"  → page {page}, {count} records ใหม่", end='\r')
        page += 1
        time.sleep(1)

    print(f"\n[+] OTX เพิ่ม {count} records ใหม่")
    return count

def print_summary():
    print("\n" + "="*50)
    print("📊 สรุปข้อมูลทั้งหมด")
    print("="*50)
    total = 0
    for filename in ['abusech.jsonl', 'cve.jsonl', 'otx.jsonl']:
        path = f"{RAW}/{filename}"
        if os.path.exists(path):
            lines = count_records(path)
            size  = os.path.getsize(path) // 1024
            print(f"  {filename:<22} {lines:>6} records  ({size} KB)")
            total += lines
        else:
            print(f"  {filename:<22} ยังไม่มีไฟล์")
    print("-"*50)
    print(f"  {'รวมทั้งหมด':<22} {total:>6} records")
    print("="*50)

if __name__ == "__main__":
    os.makedirs(RAW, exist_ok=True)
    print("🚀 เริ่มเก็บข้อมูลจาก 3 แหล่ง...")
    print_summary()
    collect_abusech()
    collect_cve(target=10000)
    collect_otx()
    print("\n✅ เสร็จแล้ว!")
    print_summary()
