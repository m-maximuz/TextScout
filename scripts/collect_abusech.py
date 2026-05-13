import requests
import json
import os

OUTPUT = os.path.expanduser("~/osint-project/data/raw/abusech.jsonl")
AUTH_KEY = os.environ.get("ABUSECH_KEY", "")

def collect():
    print("[*] Collecting from abuse.ch URLhaus...")
    headers = {"Auth-Key": AUTH_KEY}

    response = requests.get(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        headers=headers,
        timeout=30
    )
    data = response.json()
    print("[DEBUG]", list(data.keys()))

    count = 0
    with open(OUTPUT, 'a', encoding='utf-8') as f:
        for record in data.get('urls', []):
            text = f"{record.get('url','')} {record.get('threat','')}".strip()
            if text:
                entry = {
                    "text": text,
                    "threat": record.get("threat", "unknown"),
                    "source": "abuse.ch",
                    "date": record.get("date_added", "")
                }
                f.write(json.dumps(entry) + '\n')
                count += 1

    print(f"[+] บันทึกแล้ว {count} records")

if __name__ == "__main__":
    collect()
