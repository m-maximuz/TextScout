# Text OSINT AI — สรุปโปรเจกต์

**Model:** [`Maximuz23/Text-OSINT`](https://huggingface.co/Maximuz23/Text-OSINT) · **Demo:** [TextScout](https://maximuz23-textscout.hf.space)

---

## 1. ปัญหาและแนวทางแก้

**ปัญหา:** Red Team Operator ต้องอ่านรายงาน threat intel, log, โพสต์ในฟอรัม แล้วหา IOC / MITRE ATT&CK / threat actor profile ซึ่งใช้เวลานาน และต้องใช้ประสบการณ์

**แนวทาง:** Fine-tune Llama 3.2 3B ด้วยข้อมูลข่าวกรองภัยคุกคามทางไซเบอร์ เพื่อให้สามารถ:
- หา IOC จากข้อความ
- จับคู่พฤติกรรมกับเทคนิคของ MITRE ATT&CK
- รู้กลุ่มของแฮกเกอร์และประเมินช่องโหว่ได้
- **ปฏิเสธข้อมูลที่ไม่มีในระบบ**

---

## 2. จุดที่แตกต่าง: รู้จักปฏิเสธในสิ่งที่ไม่รู้

### ลองใช้ prompt ปลอมเพื่อลองทดสอบ

| Prompt (ชื่อสมมุติ) | Base Llama 3.2 3B | Fine-Tune |
|---|---|---|
| `APT-Lyrebird-77` | มั่วเรื่อง ระบุเป้าหมายเองเป็น "exercise caution from China" | *"I don't have information on APT-Lyrebird-77."* |
| `APT-Stoneraven-42` | บอก TTPs บอก malware family ว่าเป็น `Stoneraven-42-0.9.1` | *"I don't have information on APT-Stoneraven-42."* |
| `CVE-9999-987654` | ปฏิเสธแต่ยาว | *"It might be embargoed, withdrawn, or fictional."* |

### ข้อจำกัด

1. **มั่วข้อมูลออกมาอยู่เล็กน้อย**
2. **จำ template** — ROUGE-L/BERTScore ที่สูงส่วนหนึ่งมาจากโมเดล reproduce format ที่เทรน
3. **มีชื่อของกลุ่มแฮกเกอร์น้อย** — MITRE document group ไว้แค่ ~155 ตัว เพิ่มมากกว่านี้ = ต้องแต่ง actor
4. **free-text มีรูปแบบเดียว** — ตอนนี้มีแต่ threat-report shape ยังไม่มี phishing email / log / pentest note (ยังไม่มี source จริงที่ไม่ต้อง generate)

---

## 3. การรวบรวมข้อมูล

### v1 — เก็บข้อมูลรอบแรก (23 sources, 114,403 records หลังทำความสะอาด)

ข้อมูลดิบ 312K records จาก 23 แหล่งสาธารณะ (NVD, ExploitDB, GHSA, CISA KEV, MITRE ATT&CK, OTX, ThreatFox, abuse.ch URLhaus, arXiv cs.CR, Wikipedia security, Atomic Red Team) + community feeds (Telegram channels, BleepingComputer, Mandiant Blog, SANS ISC, VirusTotal) + HuggingFace datasets (Fenrir, CTI, HackerNews, Cyber v1, MISP Galaxy) + log data (Loghub)

ตัดทิ้ง 3 sources: `hf_phishing_email` (เป็น spam), `hf_phishing` (45% URL เปล่า), `security_news` (91% ซ้ำกับ BleepingComputer)

เพิ่ม **820 ตัวอย่างที่ไม่แน่นอน** สำหรับสอนให้โมเดลปฏิเสธ (CVE/actor ปลอม + ข้อมูลไม่พอ ฯลฯ)

### v1 → v2.3


#### Sources 13 ตัวที่ถูกตัดออก แบ่งเป็น 4 ประเภท:

**(A) ตัวที่สอนให้โมเดลหลอน** — คำตอบใน assistant มีข้อมูล (เช่น ชื่อ actor, CVE-ID, domain) ที่ user ไม่ได้พิมพ์มา ทีนี่พอ input ข้อมูลมาไม่พอทำให้ตัวโมเดลมั่วข้อมูลขึ้นมา

| Source | Records | Drop ที่ | สิ่งที่เห็น |
|---|---:|---|---|
| hf_fenrir | 18,943 | v2.0 | **54%** ของ assistant responses ใส่คำว่า "Conti" เมื่อ "Conti" ไม่ได้อยู่ใน user input — cleaning template กำลังสอน Conti attribution |
| misp_galaxy | 3,761 | v2.2 | **100%** emit template `Entry Type / Name / Attribution Value: MISP Galaxy` — สอนให้ lift domain เป็น actor name (เป็นสาเหตุของ SpaceX → "Airdrop-Update") |
| hf_cyber_v1 | 1,637 | v2.3 | **87%** ของ records ที่ mention APT มี APT ใน assistant ที่ไม่อยู่ใน user input + 97% domain-fab + 97% CVE-fab — ตัวจริงของ SpaceX → APT28 + Telegram → breachforus |
| cve (NVD downsampled) | 1,137 | v2.3 | **100%** ของ 1,137 records ใส่ CVE-ID ใน assistant ที่ไม่มีใน user input" |

**(B) Template collapse** — assistant output เหมือนกันทุก record ไม่ว่า input จะเป็นอะไร ทำให้โมเดลไม่สนใจ input ของ user

| Source | Records | Drop ที่ | สิ่งที่เห็น |
|---|---:|---|---|
| hf_loghub | 3,223 | v2.0 | **99.8%** identical boilerplate ที่ตอบ Apache log line ธรรมดาว่าเป็น "attack" |
| hf_cti | 7,537 | v2.0 | **93%** เป็น refusal template "Not explicitly named" + "No machine-parseable IOCs" |
| hf_hackernews | 4,986 | v2.0 | **86%** มี assistant ซ้ำกันระหว่าง records |
| bleepingcomputer | 110 | v2.0 | **78%** templated outputs |
| telegram | 3,331 | v2.2 | **100%** emit OPSEC boilerplate template + 50% fabricate "vxunderground" attribution |
| mitre_attack | 2,167 | v2.3 | top 5 boilerplate assistants ครอบ **45%** ของ source (356× / 213× / 210× / 126× / 66× identical regardless of which technique user mentioned) |

**(C) เล็กเกินไป** — records น้อยเกินไป

| Source | Records | Drop ที่ | สิ่งที่ audit วัดได้ |
|---|---:|---|---|
| mandiant_blog | 20 | v2.0 | เล็กเกินไป + 40% และก็มี Conti ติดมาด้วย |
| sans_isc | 4 | v2.0 | script ที่เขียนพังทำให้เก็บได้แค่ 4 records |
| virustotal | 43 | v2.0 | URL dumps 10 คำต่อ record ไม่มีเนื้อหา |

**(D) Format incompatibility** — base model reproduce รูปแบบนี้ไม่ได้สะอาด

| Source | Records | Drop ที่ | สิ่งที่ audit วัดได้ |
|---|---:|---|---|
| hf_cyber_v1 `<think>` subset | 224 | v2.2 | CoT format `<think>` ที่ Llama 3.2 3B 4-bit reproduce ไม่ได้สะอาด → output collapse เป็น repetition loop |

### ชุดข้อมูล v2.3

| Source | Records | What It Is |
|---|---:|---|
| exploitdb | 19,199 | metadata ของ public exploit |
| ghsa | 5,480 | GitHub Security Advisories |
| arxiv_security | 4,635 | งานวิจัย cs.CR |
| threatfox | 4,366 | IOC ของ malware |
| hf_wikipedia_security | 2,732 | Wikipedia security articles (CC BY-SA 3.0) |
| atomic_red_team | 1,495 | ATT&CK testing procedures |
| cisa_kev | 1,396 | ช่องโหว่ที่ CISA ยืนยันถูกโจมตีจริง |
| abusech | 1,133 | URL malware feeds (URLhaus) |
| **synthetic_uncertainty** | **818** | **Claude Opus 4.7 generated** |
| otx | 117 | AlienVault Threat Intelligence |
| **Total** | **41,371** | (10 sources) |

**Split:** train 36,552 / valid 3,070 / test 3,082 (stratified 85/7.5/7.5 ต่อ source)

**Composition v2.3:** 98.0% human-curated (จาก threat-intel feeds และ public sources) / 2.0% AI-generated (เฉพาะ honesty refusal records ที่สร้างด้วย Claude Opus 4.7)

v3:

- **ตัด arxiv + wikipedia**
- **de-boilerplate** source ที่เหลือ — ลอก canned prose tail ทิ้ง เหลือแต่ grounded extraction (เช่น exploitdb answer สั้นลงจาก 505 → 106 ตัวอักษร)
- **cap** source ใหญ่ ไม่ให้ format ไหนครอบงำ (exploitdb 46% → 21%)
- **เพิ่มข้อมูลของจริง** — MITRE ATT&CK groups/techniques/software, CISA KEV + NVD CVEs, OTX pulses (รายงานภัยจริง สอนให้ดึงเฉพาะที่มีในข้อความ และบอก "no attribution provided" เมื่อไม่ระบุ actor)
- **evidence-gated honesty** — positive (input มี record จริง → ตอบ) คู่กับ negative (lookup ว่าง → ปฏิเสธ)

### ชุดข้อมูล v3 (ปัจจุบัน)

| Source | Records | What It Is |
|---|---:|---|
| exploitdb | 3,489 | metadata ของ public exploit |
| ghsa | 3,000 | GitHub Security Advisories |
| otx_pulse | 2,292 | รายงานภัยจาก OTX |
| atomic_red_team | 1,478 | ATT&CK testing procedures |
| threatfox | 1,458 | IOC ของ malware |
| cisa_kev | 1,379 | ช่องโหว่ที่ CISA ยืนยันถูกโจมตีจริง |
| abusech | 1,133 | URL malware feeds |
| **synthetic_uncertainty** | **671** | **honesty signal (Claude Opus) — refusing CVE/actor ปลอม** |
| mitre_technique | 600 | อธิบาย technique |
| mitre_software | 345 | malware/tool นี้ actor ไหนใช้ |
| real_cve | 300 | ประเมิน CVE จาก record ที่ป้อนให้ |
| real_actor | 171 | profile actor จาก record ของ MITRE |
| otx | 83 | AlienVault Threat Intelligence |
| **Total** | **16,399** | (13 sources) |

**Split:** train 13,918 / valid 1,238 / test 1,243

**Composition v3:** ~96% real open-source extraction (MITRE / KEV / NVD / OTX / ExploitDB / GHSA / ThreatFox / abuse.ch) / ~4% ai gen

---

## 4. EDA และผลการฝึก v3

EDA แบบเต็มพร้อมกราฟ: [`eda.ipynb`](eda.ipynb) — กราฟ PNG: [`reports/eda/`](reports/eda/)

### Dataset characteristics (v3, 16,399 records)
- **User message length**: mean 844 chars, median 462, p99 3,503
- **IOC coverage**: 72.7% ของ records มี IOC อย่างน้อย 1 ตัว (เพิ่มจาก v1 ที่ 47.8% — record น้อยลงแต่แน่นขึ้น)
- **MITRE ATT&CK**: 781 techniques, kill chain ครบ 10/10 phase

### ผลทดสอบ — 5 metrics (base Llama 3.2 3B vs Fine-tune, test 700 + probe 80)

| Metric | Base | Fine-tune | อ่านยังไง |
|---|---:|---:|---|
| **NER F1** (extraction) | 0.604 | **0.880** | ดึง IOC / CVE / ATT&CK ได้ดี|
| **Hallucination** (ต่ำ=ดี) | 0.240 | **0.088** | ไม่ค่อยมั่ว |
| **Honesty F1** (refuse) | 0.621 | **0.987** | ปฏิเสธได้ดี |
| Honesty accuracy | 0.725 | **0.988** | |
| BERTScore | 0.819 | 0.979 | ส่วนหนึ่งมาจากจำ format |
| ROUGE-L | 0.137 | 0.887 | **ส่วนใหญ่** มาจากจำ format |

**per-category honesty (fine-tune):** fake_cve 1.00 / fake_actor 0.95 / real_actor 1.00 / real_cve 1.00 — ปฏิเสธของปลอมได้ และไม่ over-refuse

**ที่ยังพลาด:** โมเดลยังมีหลุดมั่วข้อมูลออกมาเล็กน้อย (มากๆ)

---

## 5. อ้างอิง

| Source | URL | License |
|---|---|---|
| Exploit-DB | https://www.exploit-db.com | Offensive Security |
| GHSA | https://github.com/advisories | GitHub ToS |
| arXiv cs.CR | https://arxiv.org | arXiv license (v1–v2.3 source; dropped in v3) |
| ThreatFox | https://threatfox.abuse.ch | CC0 |
| Wikipedia (wikimedia/wikipedia) | huggingface.co/datasets/wikimedia/wikipedia | **CC BY-SA 3.0** (v2.3 source; dropped in v3) |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | MIT |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Public Domain |
| abuse.ch URLhaus | https://urlhaus.abuse.ch | CC0 |
| AlienVault OTX | https://otx.alienvault.com | Community |
| MITRE ATT&CK | https://attack.mitre.org | MITRE (STIX, free use) |
| NVD | https://nvd.nist.gov | Public Domain |
| Synthetic uncertainty | Claude Opus 4.7 (Anthropic) | n/a |

### Sources ที่ถูกตัดออก
- **v2.0 (8)**: hf_fenrir, hf_loghub, hf_cti, hf_hackernews, bleepingcomputer, mandiant_blog, sans_isc, virustotal
- **v2.2 (2 + subset)**: telegram, misp_galaxy, hf_cyber_v1 `<think>` subset
- **v2.3 (3)**: hf_cyber_v1, cve (NVD downsampled), mitre_attack
- **v3 (2)**: arxiv_security, hf_wikipedia_security

### Sources ที่เพิ่มใน v3
MITRE ATT&CK groups / techniques / software (STIX), CISA KEV + NVD (enrich CVE), OTX pulses; ส่วน honesty signal ~4% สร้างด้วย Claude Opus (refusing CVE/actor ปลอม)

### License
- **Code & model**: **BigScience Open RAIL-M** — see [`LICENSE`](LICENSE) (open use ภายใต้ข้อจำกัดการใช้งานใน Attachment A: ห้ามใช้ผิดกฎหมาย / มุ่งร้าย / ละเมิดสิทธิ์)
