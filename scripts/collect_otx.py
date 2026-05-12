import requests
import json
import os

OUTPUT = os.path.expanduser("~/osint-project/data/raw/otx.jsonl")
OTX_KEY = "698c7f352ff347e48ff4edac061e9e26b4a2ffbca2da64d2a8fc99e05e8b5386"

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
