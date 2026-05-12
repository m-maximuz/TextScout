import requests
import json
import os

OUTPUT = os.path.expanduser("~/osint-project/data/raw/cve.jsonl")

def collect():
    print("[*] Collecting CVE from NVD...")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100"
    response = requests.get(url, timeout=30)
    data = response.json()

    count = 0
    with open(OUTPUT, 'a', encoding='utf-8') as f:
        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            descs = cve.get('descriptions', [])
            text = next((d['value'] for d in descs if d['lang'] == 'en'), None)
            if text:
                entry = {
                    "text": text,
                    "cve_id": cve['id'],
                    "source": "nvd_mitre",
                    "date": cve.get('published', '')
                }
                f.write(json.dumps(entry) + '\n')
                count += 1

    print(f"[+] บันทึกแล้ว {count} records → {OUTPUT}")

if __name__ == "__main__":
    collect()
