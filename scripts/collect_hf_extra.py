import os, json, time, hashlib, re
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

# ---- Phishing Dataset (ealvaradob) ----
def collect_phishing():
    print("\n[*] HuggingFace: ealvaradob/phishing-dataset...")
    path = f"{RAW}/hf_phishing.jsonl"
    seen = load_existing(path)
    count = 0
    try:
        os.environ["HF_TOKEN"] = HF_KEY
        # มี 4 subsets: combined, email, sms, url
        subsets = ["email", "sms", "url"]
        for subset in subsets:
            try:
                dataset = load_dataset(
                    "ealvaradob/phishing-dataset",
                    subset,
                    split="train"
                )
                for record in dataset:
                    text = str(record.get('text', '') or '').strip()
                    label = record.get('label', -1)
                    if len(text) > 20:
                        count += save(path, {
                            "text":   text,
                            "label":  "phishing" if label == 1 else "benign",
                            "source": f"phishing_{subset}",
                            "date":   ""
                        }, seen)
                print(f"  → subset {subset}: {count} records รวม")
            except Exception as e:
                print(f"  [!] subset {subset}: {e}")
            time.sleep(1)
    except Exception as e:
        print(f"  [!] Phishing dataset error: {e}")
    print(f"\n[+] Phishing dataset เพิ่ม {count} records ใหม่")
    return count

# ---- Phishing Email (zefang-liu) ----
def collect_phishing_email():
    print("\n[*] HuggingFace: zefang-liu/phishing-email-dataset...")
    path = f"{RAW}/hf_phishing_email.jsonl"
    seen = load_existing(path)
    count = 0
    try:
        os.environ["HF_TOKEN"] = HF_KEY
        dataset = load_dataset(
            "zefang-liu/phishing-email-dataset",
            split="train"
        )
        print(f"  fields: {dataset.column_names}")
        for record in dataset:
            # หา text field
            text = str(
                record.get('Email Text') or
                record.get('text') or
                record.get('body') or
                record.get('content') or ''
            ).strip()
            label_raw = record.get('Email Type') or record.get('label') or ''
            label = "phishing" if "phish" in str(label_raw).lower() else "benign"
            if len(text) > 20:
                count += save(path, {
                    "text":   text[:2000],  # จำกัด 2000 ตัว
                    "label":  label,
                    "source": "phishing_email",
                    "date":   ""
                }, seen)
            if count % 1000 == 0 and count > 0:
                print(f"  → {count} records", end='\r')
    except Exception as e:
        print(f"  [!] Phishing email error: {e}")
    print(f"\n[+] Phishing email เพิ่ม {count} records ใหม่")
    return count

# ---- Hacker News (filter เฉพาะ security topics) ----
def collect_hackernews():
    print("\n[*] HuggingFace: open-index/hacker-news (security topics only)...")
    path = f"{RAW}/hf_hackernews.jsonl"
    seen = load_existing(path)
    count = 0

    security_keywords = [
        "vulnerability", "exploit", "malware", "ransomware", "breach",
        "hack", "phishing", "zero-day", "cve", "cybersecurity", "infosec",
        "penetration", "backdoor", "botnet", "ddos", "injection", "xss",
        "sql injection", "privilege escalation", "threat", "attack"
    ]

    try:
        os.environ["HF_TOKEN"] = HF_KEY
        # ดึงแค่ 1 เดือนล่าสุด เพราะ dataset ใหญ่มาก
        dataset = load_dataset(
            "open-index/hacker-news",
            data_files="data/2024/2024-01.parquet",
            split="train",
            streaming=True
        )
        checked = 0
        for record in dataset:
            text = str(record.get('text') or record.get('title') or '').strip()
            text = re.sub(r'<[^>]+>', '', text).strip()

            if len(text) < 30:
                checked += 1
                continue

            # กรองเฉพาะ security topics
            text_lower = text.lower()
            if any(kw in text_lower for kw in security_keywords):
                count += save(path, {
                    "text":   text[:1000],
                    "source": "hackernews_security",
                    "date":   str(record.get('time', ''))
                }, seen)

            checked += 1
            if checked % 50000 == 0:
                print(f"  → เช็ค {checked:,} posts, ได้ {count} security records", end='\r')

            if count >= 5000:
                print(f"\n  [+] ได้ครบ 5000 records แล้ว")
                break

    except Exception as e:
        print(f"  [!] Hacker News error: {e}")
    print(f"\n[+] Hacker News security เพิ่ม {count} records ใหม่")
    return count

# ---- Summary ----
def print_summary():
    print("\n" + "="*55)
    print("📊 สรุปไฟล์ใหม่")
    print("="*55)
    total = 0
    files = [
        'hf_phishing.jsonl',
        'hf_phishing_email.jsonl',
        'hf_hackernews.jsonl'
    ]
    for filename in files:
        path = f"{RAW}/{filename}"
        if os.path.exists(path):
            lines = count_records(path)
            size  = os.path.getsize(path) // 1024
            print(f"  {filename:<30} {lines:>6} records  ({size} KB)")
            total += lines
        else:
            print(f"  {filename:<30} ยังไม่มีไฟล์")
    print("-"*55)
    print(f"  {'รวมใหม่':<30} {total:>6} records")
    print("="*55)

if __name__ == "__main__":
    os.makedirs(RAW, exist_ok=True)
    print("🚀 เริ่มเก็บข้อมูล Raw & Contextual...")
    collect_phishing()
    collect_phishing_email()
    collect_hackernews()
    print("\n✅ เสร็จแล้ว!")
    print_summary()
