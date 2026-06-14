import requests, json, os, time, hashlib
import xml.etree.ElementTree as ET
from datasets import load_dataset

RAW = os.path.expanduser("~/osint-project/data/raw")
HF_KEY = os.environ.get("HF_KEY")

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

def get_request(url, headers=None, retries=5, sleep=5):
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 200 and r.text.strip():
                return r
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

# ---- HuggingFace Dataset 1: Cybersecurity-Dataset-v1 ----
def collect_hf_cyber_v1():
    print("\n[*] HuggingFace: AlicanKiraz0/Cybersecurity-Dataset-v1...")
    path = f"{RAW}/hf_cyber_v1.jsonl"
    seen = load_existing(path)
    count = 0
    try:
        os.environ["HF_TOKEN"] = HF_KEY
        dataset = load_dataset(
            "AlicanKiraz0/Cybersecurity-Dataset-v1",
            split="train"
        )
        for record in dataset:
            user = record.get('user', '')
            assistant = record.get('assistant', '')
            text = f"{user} {assistant}".strip()
            if len(text) > 30:
                count += save(path, {
                    "text":   text,
                    "source": "hf_cybersecurity_v1",
                    "date":   ""
                }, seen)
            if count % 1000 == 0 and count > 0:
                print(f"  → {count} records", end='\r')
    except Exception as e:
        print(f"  [!] Error: {e}")
    print(f"\n[+] Cybersecurity-Dataset-v1 เพิ่ม {count} records ใหม่")
    return count

# ---- HuggingFace Dataset 2: Fenrir v2.0 (Adversarial + Chain-of-thought) ----
def collect_hf_fenrir():
    print("\n[*] HuggingFace: AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0...")
    path = f"{RAW}/hf_fenrir.jsonl"
    seen = load_existing(path)
    count = 0
    try:
        os.environ["HF_TOKEN"] = HF_KEY
        dataset = load_dataset(
            "AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0",
            split="train"
        )
        for record in dataset:
            user = record.get('user', '')
            assistant = record.get('assistant', '')
            text = f"{user} {assistant}".strip()
            if len(text) > 30:
                count += save(path, {
                    "text":   text,
                    "source": "hf_fenrir_v2",
                    "date":   ""
                }, seen)
            if count % 1000 == 0 and count > 0:
                print(f"  → {count} records", end='\r')
    except Exception as e:
        print(f"  [!] Error: {e}")
    print(f"\n[+] Fenrir v2.0 เพิ่ม {count} records ใหม่")
    return count

# ---- HuggingFace Dataset 3: CTI (Cyber Threat Intelligence) ----
def collect_hf_cti():
    print("\n[*] HuggingFace: mrmoor/cyber-threat-intelligence...")
    path = f"{RAW}/hf_cti.jsonl"
    seen = load_existing(path)
    count = 0
    try:
        os.environ["HF_TOKEN"] = HF_KEY
        dataset = load_dataset(
            "mrmoor/cyber-threat-intelligence",
            split="train"
        )
        for record in dataset:
            text = str(
                record.get('text') or
                record.get('content') or
                record.get('description') or ''
            ).strip()
            if len(text) > 30:
                count += save(path, {
                    "text":   text,
                    "source": "hf_cti",
                    "date":   ""
                }, seen)
            if count % 1000 == 0 and count > 0:
                print(f"  → {count} records", end='\r')
    except Exception as e:
        print(f"  [!] Error: {e}")
    print(f"\n[+] CTI dataset เพิ่ม {count} records ใหม่")
    return count

# ---- RSS News Feeds ----
def collect_rss():
    print("\n[*] Security News RSS Feeds...")
    path = f"{RAW}/security_news.jsonl"
    seen = load_existing(path)
    count = 0
    import re

    feeds = [
        ("https://feeds.feedburner.com/TheHackersNews",    "thehackersnews"),
        ("https://www.darkreading.com/rss.xml",            "darkreading"),
        ("https://krebsonsecurity.com/feed/",              "krebsonsecurity"),
        ("https://threatpost.com/feed/",                   "threatpost"),
        ("https://www.securityweek.com/feed",              "securityweek"),
    ]

    for feed_url, source_name in feeds:
        try:
            r = get_request(feed_url, headers={"User-Agent": "Mozilla/5.0"})
            if not r:
                print(f"  [!] ดึง {source_name} ไม่ได้ ข้ามไป")
                continue
            root = ET.fromstring(r.content)
            items = root.findall('.//item')
            feed_count = 0
            for item in items:
                title = item.findtext('title', '')
                desc  = item.findtext('description', '')
                date  = item.findtext('pubDate', '')
                text  = f"{title}. {desc}".strip()
                text  = re.sub(r'<[^>]+>', '', text).strip()
                text  = re.sub(r'\s+', ' ', text).strip()
                if len(text) > 50:
                    feed_count += save(path, {
                        "text":   text,
                        "source": source_name,
                        "date":   date
                    }, seen)
            count += feed_count
            print(f"  → {source_name}: {feed_count} records ใหม่")
            time.sleep(2)
        except Exception as e:
            print(f"  [!] Error {source_name}: {e}")

    print(f"\n[+] RSS News เพิ่ม {count} records ใหม่")
    return count

# ---- Loghub (Temporal/Log data) ----
def collect_loghub():
    print("\n[*] Loghub SSH/Linux logs จาก GitHub...")
    path = f"{RAW}/hf_loghub.jsonl"
    seen = load_existing(path)
    count = 0

    # ดึง log files โดยตรงจาก GitHub raw
    log_urls = [
        ("https://raw.githubusercontent.com/logpai/loghub/master/SSH/SSH_2k.log", "SSH"),
        ("https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log", "Linux"),
        ("https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log", "Apache"),
    ]

    for url, log_type in log_urls:
        try:
            r = get_request(url)
            if not r:
                print(f"  [!] ดึง {log_type} ไม่ได้")
                continue
            lines = r.text.strip().split('\n')
            for line in lines:
                line = line.strip()
                if len(line) > 20:
                    count += save(path, {
                        "text":     line,
                        "source":   f"loghub_{log_type}",
                        "log_type": log_type,
                        "date":     ""
                    }, seen)
            print(f"  → {log_type}: {count} records รวม")
            time.sleep(2)
        except Exception as e:
            print(f"  [!] Error {log_type}: {e}")

    print(f"\n[+] Loghub เพิ่ม {count} records ใหม่")
    return count

# ---- Wikipedia Security subset (Noisy/Normal data) ----
def collect_wikipedia_security():
    print("\n[*] HuggingFace: Wikipedia security subset...")
    path = f"{RAW}/hf_wikipedia_security.jsonl"
    seen = load_existing(path)
    count = 0

    # keywords ที่เกี่ยวกับ security แต่เป็นภาษาปกติ (สอน AI ว่าอะไรคือ normal)
    security_keywords = [
        "cybersecurity", "malware", "vulnerability", "firewall",
        "encryption", "phishing", "ransomware", "intrusion detection",
        "penetration testing", "social engineering"
    ]

    try:
        os.environ["HF_TOKEN"] = HF_KEY
        dataset = load_dataset(
            "wikimedia/wikipedia",
            "20231101.en",
            split="train",
            streaming=True  # streaming เพราะไฟล์ใหญ่มาก ประหยัด RAM
        )
        checked = 0
        for record in dataset:
            text = str(record.get('text', '')).strip()
            title = str(record.get('title', '')).lower()

            # กรองเฉพาะ article ที่เกี่ยวกับ security
            if any(kw in title or kw in text[:500].lower()
                   for kw in security_keywords):
                # ตัดแค่ 1000 ตัวอักษรแรก ไม่เอาทั้ง article
                snippet = text[:1000].strip()
                if len(snippet) > 100:
                    count += save(path, {
                        "text":   snippet,
                        "title":  record.get('title', ''),
                        "source": "wikipedia_security",
                        "date":   ""
                    }, seen)

            checked += 1
            if checked % 10000 == 0:
                print(f"  → เช็คแล้ว {checked} articles, ได้ {count} records", end='\r')

            # หยุดเมื่อได้ครบ 5000 records
            if count >= 5000:
                break

    except Exception as e:
        print(f"  [!] Wikipedia error: {e}")

    print(f"\n[+] Wikipedia security เพิ่ม {count} records ใหม่")
    return count

# ---- Summary ----
def print_summary():
    print("\n" + "="*60)
    print("📊 สรุปข้อมูลทั้งหมด")
    print("="*60)
    total = 0
    files = [
        'abusech.jsonl',
        'cve.jsonl',
        'otx.jsonl',
        'mitre_attack.jsonl',
        'bleepingcomputer.jsonl',
        'hf_cyber_v1.jsonl',
        'hf_fenrir.jsonl',
        'hf_cti.jsonl',
        'security_news.jsonl',
        'hf_loghub.jsonl',
        'hf_wikipedia_security.jsonl',
    ]
    for filename in files:
        path = f"{RAW}/{filename}"
        if os.path.exists(path):
            lines = count_records(path)
            size  = os.path.getsize(path) // 1024
            print(f"  {filename:<30} {lines:>7} records  ({size} KB)")
            total += lines
        else:
            print(f"  {filename:<30} ยังไม่มีไฟล์")
    print("-"*60)
    print(f"  {'รวมทั้งหมด':<30} {total:>7} records")
    print("="*60)

if __name__ == "__main__":
    os.makedirs(RAW, exist_ok=True)
    print("🚀 เริ่มเก็บข้อมูลจากแหล่งใหม่...")
    print_summary()
    collect_hf_cyber_v1()
    collect_hf_fenrir()
    collect_hf_cti()
    collect_rss()
    collect_loghub()
    collect_wikipedia_security()
    print("\n✅ เสร็จแล้ว!")
    print_summary()
