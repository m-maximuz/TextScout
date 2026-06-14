import json
import os
import time
import random
import urllib.request

OUT = os.path.expanduser("~/osint-project/data/04_curation_v2_4/verified_fake_cves.json")
TARGET = 150
API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

# realistic-looking candidates across real years (NOT year 9999) so the model keys on the
# empty-lookup body, not a year shortcut. Each is verified non-existent against NVD below.
rng = random.Random(11)
years = list(range(2015, 2026))


def candidates():
    seen = set()
    while True:
        y = rng.choice(years)
        n = rng.randint(1000, 99999)
        cid = f"CVE-{y}-{n}"
        if cid in seen:
            continue
        seen.add(cid)
        yield cid


def nvd_total(cid):
    req = urllib.request.Request(API + cid, headers={"User-Agent": "osint-fake-verify"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r).get("totalResults", -1)


def main():
    verified, checked = [], 0
    gen = candidates()
    while len(verified) < TARGET:
        cid = next(gen)
        checked += 1
        try:
            total = nvd_total(cid)
        except Exception as e:
            print(f"  err {cid}: {e}; backing off", flush=True)
            time.sleep(20)
            continue
        if total == 0:
            verified.append(cid)
            if len(verified) % 10 == 0:
                json.dump(verified, open(OUT, "w"), indent=1)
                print(f"  verified {len(verified)}/{TARGET} (checked {checked})", flush=True)
        time.sleep(7)  # stay under NVD's 5-req / 30s unkeyed limit
    json.dump(verified, open(OUT, "w"), indent=1)
    print(f"DONE: {len(verified)} verified-fake CVE ids (checked {checked}) -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
