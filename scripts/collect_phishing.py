import os, json, hashlib
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

def save(filepath, entry, seen):
    h = make_hash(entry['text'])
    if h in seen:
        return 0
    seen.add(h)
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    return 1

def collect():
    print("[*] HuggingFace: cybersectony/PhishingEmailDetectionv2.0...")
    path = f"{RAW}/hf_phishing.jsonl"
    seen = load_existing(path)
    count = 0

    label_map = {
        0: "legitimate_email",
        1: "phishing_email",
        2: "legitimate_url",
        3: "phishing_url"
    }

    try:
        os.environ["HF_TOKEN"] = HF_KEY
        dataset = load_dataset(
            "cybersectony/PhishingEmailDetectionv2.0",
            split="train"
        )
        print(f"  fields: {dataset.column_names}")
        for record in dataset:
            text = str(record.get('content', '') or '').strip()
            label = label_map.get(record.get('labels', -1), 'unknown')
            if len(text) > 20:
                count += save(path, {
                    "text":   text[:2000],
                    "label":  label,
                    "source": "phishing_detection_v2",
                    "date":   ""
                }, seen)
            if count % 10000 == 0 and count > 0:
                print(f"  → {count} records", end='\r')
    except Exception as e:
        print(f"  [!] Error: {e}")

    print(f"\n[+] เพิ่ม {count} records ใหม่")
    return count

if __name__ == "__main__":
    collect()
