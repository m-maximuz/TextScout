import requests
import json
import os

OUTPUT = os.path.expanduser("~/osint-project/data/raw/otx.jsonl")
OTX_KEY = os.environ.get("OTX_KEY", "")

def collect():
    print("[*] Collecting from OTX AlienVault...")
    headers = {"X-OTX-API-KEY": OTX_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=100"
    
    r = requests.get(url, headers=headers, timeout=30)
    data = r.json()
    
    count = 0
    with open(OUTPUT, 'a', encoding='utf-8') as f:
        for pulse in data.get('results', []):
            text = f"{pulse.get('name','')} {pulse.get('description','')}".strip()
            if text:
                entry = {
                    "text": text,
                    "source": "otx_alienvault",
                    "date": pulse.get('created', '')
                }
                f.write(json.dumps(entry) + '\n')
                count += 1
    
    print(f"[+] บันทึกแล้ว {count} records")

if __name__ == "__main__":
    collect()
