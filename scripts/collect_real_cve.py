import requests
import json
import os
import time

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_KEY = os.environ.get("NVD_KEY", "")

OUTDIR = os.path.expanduser("~/osint-project/data/04_curation_v2_4")
OUTPUT = os.path.join(OUTDIR, "real_cve_raw.jsonl")
PROBE = os.path.expanduser("~/osint-project/data/05_eval_probes/honesty_probe.jsonl")
TARGET_N = 150


def probe_cve_ids():
    ids = set()
    for line in open(PROBE, encoding="utf-8"):
        r = json.loads(line)
        if r.get("category") == "real_cve":
            ids.add(r["identifier"])
    return ids


def nvd_enrich(cve_id):
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    r = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
    if r.status_code != 200:
        return {}
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        return {}
    cve = vulns[0]["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    metrics = cve.get("metrics", {})
    cvss = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            cvss = f"{data.get('baseScore','')} {data.get('baseSeverity', data.get('baseScore',''))} {data.get('vectorString','')}"
            break
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d["value"].startswith("CWE-"):
                cwes.append(d["value"])
    refs = [ref["url"] for ref in cve.get("references", [])][:6]
    return {"nvd_description": desc, "cvss": cvss, "cwes": sorted(set(cwes)), "references": refs}


def collect():
    os.makedirs(OUTDIR, exist_ok=True)
    exclude = probe_cve_ids()
    print(f"[*] Excluding {len(exclude)} probe CVE IDs from training set")

    print("[*] Downloading CISA KEV feed...")
    kev = requests.get(KEV_URL, timeout=60).json()["vulnerabilities"]

    by_year = {}
    for v in kev:
        if v["cveID"] in exclude:
            continue
        year = v["cveID"].split("-")[1]
        by_year.setdefault(year, []).append(v)
    for year in by_year:
        by_year[year].sort(
            key=lambda v: (v.get("knownRansomwareCampaignUse") == "Known", v.get("dateAdded", "")),
            reverse=True,
        )

    targets = []
    while len(targets) < TARGET_N and any(by_year.values()):
        for year in sorted(by_year, reverse=True):
            if by_year[year]:
                targets.append(by_year[year].pop(0))
                if len(targets) >= TARGET_N:
                    break

    enrich = bool(NVD_KEY)
    print(f"[*] Staging {len(targets)} CVEs. NVD enrichment: {'ON' if enrich else 'OFF (set NVD_KEY)'}")

    count = 0
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for v in targets:
            record = {
                "cve_id": v["cveID"],
                "name": v.get("vulnerabilityName", ""),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "kev_description": v.get("shortDescription", ""),
                "required_action": v.get("requiredAction", ""),
                "date_added": v.get("dateAdded", ""),
                "ransomware_use": v.get("knownRansomwareCampaignUse", ""),
                "source": "real_cve",
            }
            if enrich:
                record.update(nvd_enrich(v["cveID"]))
                time.sleep(0.7 if NVD_KEY else 6)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    sidecar = os.path.join(OUTDIR, "excluded_probe_cves.json")
    json.dump(sorted(exclude), open(sidecar, "w"), indent=2)
    print(f"[+] Wrote {count} CVE records -> {OUTPUT}")
    print(f"[+] Held-out probe CVEs recorded -> {sidecar}")


if __name__ == "__main__":
    collect()
