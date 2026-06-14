import os
import json
import time
import requests

OTX_KEY = os.environ.get("OTX_KEY", "")
OUT = os.path.expanduser("~/osint-project/data/04_curation_v2_4/otx_pulses_raw.jsonl")
MAX_PAGES = 90
PER_PAGE = 50
MIN_DESC = 200


def norm_indicators(inds):
    out = []
    for i in inds:
        out.append({"type": i.get("type", ""), "indicator": i.get("indicator", "")})
    return out


def collect():
    if not OTX_KEY:
        raise SystemExit("set OTX_KEY")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    headers = {"X-OTX-API-KEY": OTX_KEY}
    seen_desc = set()
    kept = 0
    with open(OUT, "w", encoding="utf-8") as f:
        for page in range(1, MAX_PAGES + 1):
            url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit={PER_PAGE}&page={page}"
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code != 200:
                print(f"[!] page {page} status {r.status_code}, stopping")
                break
            results = r.json().get("results", [])
            if not results:
                break
            for p in results:
                desc = (p.get("description") or "").strip()
                inds = p.get("indicators", []) or []
                attack = [a.get("id") if isinstance(a, dict) else a for a in p.get("attack_ids", []) or []]
                if len(desc) < MIN_DESC:
                    continue
                if not inds and not attack:
                    continue
                key = desc[:120]
                if key in seen_desc:
                    continue
                seen_desc.add(key)
                rec = {
                    "name": p.get("name", ""),
                    "description": desc,
                    "adversary": (p.get("adversary") or "").strip(),
                    "malware_families": [m.get("display_name") if isinstance(m, dict) else m
                                         for m in p.get("malware_families", []) or []],
                    "attack_ids": attack,
                    "industries": p.get("industries", []) or [],
                    "targeted_countries": p.get("targeted_countries", []) or [],
                    "indicators": norm_indicators(inds),
                    "references": (p.get("references") or [])[:3],
                    "source": "otx_pulse",
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                kept += 1
            time.sleep(0.3)
            if page % 10 == 0:
                print(f"  page {page}: kept so far {kept}")
    print(f"[+] Wrote {kept} quality pulses -> {OUT}")


if __name__ == "__main__":
    collect()
