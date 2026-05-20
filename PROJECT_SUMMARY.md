# Text OSINT AI — สรุปโปรเจกต์

**โมเดล (v2.3):** [`Maximuz23/Text-OSINT`](https://huggingface.co/Maximuz23/Text-OSINT)

---

## 1. ปัญหาและแนวทางแก้

**ปัญหา:** Red Team Operator ต้องอ่านรายงาน threat intel, log, โพสต์ในฟอรัม แล้วหา IOC / MITRE ATT&CK / threat actor profile ซึ่งใช้เวลานาน และต้องใช้ประสบการณ์หลายปี

**แนวทาง:** Fine-tune Llama 3.2 3B ด้วยข้อมูลข่าวกรองภัยคุกคามทางไซเบอร์ เพื่อให้สามารถ:
- หา IOC จากข้อความ
- จับคู่พฤติกรรมกับเทคนิคของ MITRE ATT&CK
- โปรไฟล์กลุ่มภัยคุกคาม + ประเมินช่องโหว่
- **ปฏิเสธข้อมูลที่ไม่มีในระบบ**

---

## 2. จุดที่แตกต่าง: รู้จักปฏิเสธในสิ่งที่ไม่รู้

### ลองใช้ prompt ปลอมเพื่อลองทดสอบ

| Prompt (ชื่อสมมุติ) | Base Llama 3.2 3B | Fine-Tune |
|---|---|---|
| `APT-Lyrebird-77` | มั่วเรื่อง ระบุเป้าหมายเองเป็น "exercise caution from China" | *"I don't have information on APT-Lyrebird-77."* |
| `APT-Stoneraven-42` | บอก TTPs บอก malware family ว่าเป็น `Stoneraven-42-0.9.1` | *"I don't have information on APT-Stoneraven-42."* |
| `CVE-9999-987654` | ปฏิเสธแต่ยาว | *"It might be embargoed, withdrawn, or fictional."* |


### ทำได้โดย
สร้าง 820 ตัวอย่างที่ไม่แน่นอนที่สร้างด้วย Claude Opus 4.7 (CVE ปลอม 150, actor ปลอม 150, ข้อมูลไม่พอ 100, ให้หาข้อมูล real-time 100, ค่า hash มั่ว 100, นอกขอบเขต 80, กำกวม 80, ให้ทำนายอนาคต 60) โดยแต่ละตัวอย่างใช้รูปแบบประโยคต่างกัน

### ข้อจำกัด

1. **จะสร้างข้อมูลขึ้นมาเมื่อ input เป็น Free-text* — เมื่อ input ไม่มีโครงสร้าง โมเดลสร้างข้อมูลขึ้นมา
2. **จำ template** — test loss (0.627) ดูดีกว่า valid loss (0.769) เดาว่าเพราะ test records บางส่วนใกล้เคียงกับ training templates
3. **มั่วค่า Hash** — ในข้อมูลที่ใช้ฝึกสอนครอบคลุม CVE/actor ปลอม แต่ไม่ครอบคลุม hash ปลอม
4. **ขนาดของตัว 3B model** — เมื่อ input ยาวและต้องคัดลอก IOC/hash ตรงตัวโมเดลอาจเปลี่ยนตัวอักษรไป 1-2 ตัว เช่น airdrop-update[.]com เป็น airdrop/update[.]com

---

## 3. การรวบรวมข้อมูล

### v1 — เก็บข้อมูลรอบแรก (22 sources, 114,403 records หลังทำความสะอาด)

ข้อมูลดิบ 312K records จาก 22 แหล่งสาธารณะ (NVD, ExploitDB, GHSA, CISA KEV, MITRE ATT&CK, OTX, ThreatFox, abuse.ch URLhaus, arXiv cs.CR, Wikipedia security, Atomic Red Team) + community feeds (Telegram channels, BleepingComputer, Mandiant Blog, SANS ISC, VirusTotal) + HuggingFace datasets (Fenrir, CTI, HackerNews, Cyber v1, MISP Galaxy) + log data (Loghub)

ตัดทิ้ง 3 sources: `hf_phishing_email` (เป็น Enron spam), `hf_phishing` (45% URL เปล่า), `security_news` (91% ซ้ำกับ BleepingComputer)

เพิ่ม **820 ตัวอย่างที่ไม่แน่นอน** สำหรับสอนให้โมเดลปฏิเสธ (CVE/actor ปลอม + ข้อมูลไม่พอ ฯลฯ)

### v1 → v2.3

เนื่องจากพี่เพิชบอกให้ผมไปดู data เพื่อหาว่าอันไหนควรเอาออก

#### Sources 13 ตัวที่ถูกตัดออก แบ่งเป็น 4 ประเภท:

**(A) ตัวที่สอนให้โมเดลหลอน** — คำตอบใน assistant มีข้อมูล (เช่น ชื่อ actor, CVE-ID, domain) ที่ user ไม่ได้พิมพ์มา ทีนี่พอ input ข้อมูลมาไม่พอทำให้ตัวโมเดลมั่วข้อมูลขึ้นมา

| Source | Records | Drop ที่ | สิ่งที่เห็น |
|---|---:|---|---|
| hf_fenrir | 18,943 | v2.0 | **54%** ของ assistant responses ใส่คำว่า "Conti" เมื่อ "Conti" ไม่ได้อยู่ใน user input — cleaning template กำลังสอน Conti attribution |
| misp_galaxy | 3,761 | v2.2 | **100%** emit template `Entry Type / Name / Attribution Value: MISP Galaxy` — สอนให้ lift domain เป็น actor name (เป็นสาเหตุของ SpaceX → "Airdrop-Update") |
| hf_cyber_v1 | 1,637 | v2.3 | **87%** ของ records ที่ mention APT มี APT ใน assistant ที่ไม่อยู่ใน user input + 97% domain-fab + 97% CVE-fab — ตัวจริงของ SpaceX → APT28 + Telegram → breachforus |
| cve (NVD downsampled) | 1,137 | v2.3 | **100%** ของ 1,137 records ใส่ CVE-ID ใน assistant ที่ไม่มีใน user input — สอน "make up authoritative ID from description" |

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

#### สรุปการ iterate

| Version | วันที่ | Records | Sources ที่ตัด | ประเภทปัญหาที่แก้ |
|---|---|---:|---|---|
| v2.0 | 16 พ.ค. | 53,469 | 8 sources | hallucination teacher (hf_fenrir) + template collapse + too small |
| v2.1 | 17 พ.ค. | 53,469 | (ไม่ตัด — surgical fix) | 3× oversample synthetic_uncertainty + MAX_STEPS 300→500 เพื่อแก้ honesty regression ของ v2.0 |
| v2.2 | 18 พ.ค. | 46,312 | 3 sources/subset | hallucination teacher (misp_galaxy) + template collapse (telegram) + format issue (`<think>`) |
| **v2.3** | **19 พ.ค.** | **41,371** | **3 sources** | **hallucination teachers ที่เหลือ (hf_cyber_v1 + cve) + template collapse ขนาดใหญ่ (mitre_attack)** |

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

**Split:** train 36,552 / valid 3,070 / test 3,082 (stratified 85/7.5/7.5 ต่อ source) — ใน train, synthetic_uncertainty oversample 3× = honesty proportion 5.70%

**Composition v2.3:** 98.0% human-curated (จาก threat-intel feeds และ public sources) / 2.0% AI-generated (เฉพาะ honesty refusal records ที่สร้างด้วย Claude Opus 4.7)

---

## 4. EDA และผลการฝึก v2.3

EDA แบบเต็มพร้อมกราฟ: [`eda.ipynb`](eda.ipynb) — กราฟ PNG: [`reports/eda/`](reports/eda/)

### Dataset characteristics (v2.3, 41,371 records)
- **User message length**: mean 658 chars, median 325, p99 2,317
- **IOC coverage**: 60.7% ของ records แต่ละ record มี IOC อย่างน้อย 1 ตัว (CVE 46.2% / domain 15.1% / URL 9.9% / IP 4.2% / hash 2.3%)
- **MITRE ATT&CK**: 337 techniques, 3,104 mentions (ลดลงจาก v1's 858 techniques เพราะ mitre_attack source ถูกตัด)


### Loss curve

| Step | Train | Valid |
|---:|---:|---:|
| 100 | 0.894 | 0.839 |
| 300 | 0.766 | 0.778 |
| 500 | 0.731 | **0.769** |
| Test | | 0.627 |

**Validation loss 0.7688** (v2.2: 0.830 / v2.1: 0.850 / v2.0: 0.881 / v1: 0.910)

### ผลทดสอบ (base Llama 3.2 3B vs Fine-tune Llama 3.2 3B)


| # | Prompt | Base | Fine-tune | Winner |
|---:|---|---|---|:---:|
| 1 | IOC Extraction (Cobalt Strike) | extract IP/port ได้ ไม่ defang | defang ถูก + structured analysis | **Fine-tune** |
| 2 | Threat Actor Profile (SpaceX TTPs) | map TTPs ทั้ง 5 ข้อถูก | แต่งเติมข้อมูล | **Base** |
| 3 | CVE-2021-44228 (Log4j) | analysis ยาวๆ T-codes ผิด | สั้น KEV flag ถูก | **Fine-tune** |
| 4 | Telegram VERCEL/edgenull | แยก `edgenull` ถูก ระบุ GitHub PAT vector | แต่งเติมข้อมูล | **Base** |
| 5 | Honesty: CVE-9999-987654 ปลอม | ปฏิเสธ | ปฏิเสธ (สั้นกว่า) | **Draw** |
| 6 | Honesty: APT-Lyrebird-77 ปลอม | fabricate profile | **ปฏิเสธ** | **Fine-tune** |
| 7 | Honesty: APT-Stoneraven-42 ปลอม | fabricate เต็ม | **ปฏิเสธ** | **Fine-tune** |

**สรุป: Fine-tune ชนะ 4 / Base ชนะ 2 / เสมอ 1**

และผมก็ลองสุ่มออกมา 5 records จาก  test records (Wikipedia / ExploitDB×2 / GHSA / CISA KEV) — Fine-tune ชนะทั้งหมด แต่บางส่วนเป็นการจำ template

---

## 5. อ้างอิง

| Source | URL | License |
|---|---|---|
| Exploit-DB | https://www.exploit-db.com | Offensive Security |
| GHSA | https://github.com/advisories | GitHub ToS |
| arXiv cs.CR | https://arxiv.org | arXiv license |
| ThreatFox | https://threatfox.abuse.ch | CC0 |
| Wikipedia (wikimedia/wikipedia) | huggingface.co/datasets/wikimedia/wikipedia | **CC BY-SA 3.0** (share-alike applies to model) |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | MIT |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Public Domain |
| abuse.ch URLhaus | https://urlhaus.abuse.ch | CC0 |
| AlienVault OTX | https://otx.alienvault.com | Community |
| Synthetic uncertainty | Claude Opus 4.7 (Anthropic) | n/a |

### Sources ที่ถูกตัดออก v1 → v2.3
- **v2.0 (8)**: hf_fenrir, hf_loghub, hf_cti, hf_hackernews, bleepingcomputer, mandiant_blog, sans_isc, virustotal
- **v2.2 (2 + subset)**: telegram, misp_galaxy, hf_cyber_v1 `<think>` subset
- **v2.3 (3)**: hf_cyber_v1, cve (NVD downsampled), mitre_attack

### License
- **Code** (collectors, scripts, notebooks): **MIT** — see [`LICENSE`](LICENSE)
- **Model weights** (HuggingFace): **CC BY-SA 3.0** — เนื่องจาก wikimedia/wikipedia (คือ 5.6% ของ v2.3 train) มี share-alike clause
