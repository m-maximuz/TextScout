import json, os

RAW = os.path.expanduser("~/osint-project/data/raw")

files = [
    'abusech.jsonl', 'bleepingcomputer.jsonl', 'cisa_kev.jsonl',
    'cve.jsonl', 'hf_cti.jsonl', 'hf_cyber_v1.jsonl',
    'hf_fenrir.jsonl', 'hf_hackernews.jsonl', 'hf_loghub.jsonl',
    'hf_phishing.jsonl', 'hf_phishing_email.jsonl',
    'hf_wikipedia_security.jsonl', 'mitre_attack.jsonl',
    'otx.jsonl', 'security_news.jsonl', 'telegram.jsonl',
    'threatfox.jsonl', 'virustotal.jsonl'
]

for filename in files:
    path = f"{RAW}/{filename}"
    if not os.path.exists(path):
        continue
    with open(path, 'r', encoding='utf-8') as f:
        line = f.readline()
        try:
            record = json.loads(line.strip())
            keys   = list(record.keys())
            text   = str(record.get('text', ''))[:80]
            print(f"\n{'='*60}")
            print(f"FILE: {filename}")
            print(f"KEYS: {keys}")
            print(f"TEXT: {text}")
        except Exception as e:
            print(f"\nERROR {filename}: {e}")
