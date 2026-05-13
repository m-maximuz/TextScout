# Text OSINT AI — สรุปโปรเจกต์ฉบับสมบูรณ์

**โมเดล:** [`Maximuz23/Text-OSINT`](https://huggingface.co/Maximuz23/Text-OSINT)

---

## 1. ปัญหาที่ต้องการแก้

### ปัญหา
Red Team Operator ต้องทำ **Open Source Intelligence (OSINT)** ทั้งก่อนและระหว่างการปฏิบัติงาน — อ่านรายงานภัยคุกคาม, คำอธิบายช่องโหว่, ไฟล์ log, โพสต์ในฟอรัม, และข้อความบนดาร์กเว็บเพื่อสกัดข่าวกรองที่นำไปใช้ได้ งานลักษณะนี้:
- **ใช้เวลามาก:** รายงานภัยคุกคาม 1 ฉบับใช้เวลาวิเคราะห์ด้วยมือ 30–60 นาที
- **ไม่สม่ำเสมอ:** นักวิเคราะห์แต่ละคนสกัดสิ่งที่แตกต่างกันจากข้อความเดียวกัน
- **พึ่งพาความเชี่ยวชาญสูง:** ความเข้าใจ IOC, TTP, MITRE ATT&CK และการระบุแหล่งที่มาของภัยคุกคามต้องใช้ประสบการณ์หลายปี

### แนวทางแก้
Fine-tune โมเดล Llama 3.2 3B ด้วยข้อมูลข่าวกรองภัยคุกคามทางไซเบอร์ เพื่อให้สามารถ:
- สกัด Indicators of Compromise (IOC) จากข้อความใดๆ
- จับคู่พฤติกรรมที่อธิบายไว้กับเทคนิคของ MITRE ATT&CK
- โปรไฟล์กลุ่มภัยคุกคามจากคำอธิบายที่เขียนเป็นข้อความ
- ประเมินช่องโหว่จากมุมมองเชิงรุก (offensive)
- ปะติดปะต่อ Timeline การโจมตีจากข้อความ log
- **ปฏิเสธการแต่งข่าวกรองเกี่ยวกับชื่อ/รหัสที่ไม่รู้จัก** — นี่คือจุดเด่นหลักของโปรเจกต์

---

## 2. จุดที่แตกต่างจากโมเดลตัวอื่น: รู้จักปฏิเสธในสิ่งที่ตัวโมเดลนั้นไม่มีอยู่

จุดเด่นของโมเดลตัวนี้คือเป็นโมเดลที่ถูกสอนให้ **ปฏิเสธข้อมูล** ได้ แทนที่จะมั่วเรื่องขึ้นมาเหมือนที่โมเดลตัวอื่นๆทำ

**พรอมต์ทดสอบ:** *"Profile threat actor APT-Lyrebird-77."* (เป็นชื่อที่ตั้งขึ้นมาเอง และตรวจสอบแล้วว่าไม่มีในข้อมูลที่ใช้ฝึกฝน)

| Model | Output |
|---|---|
| Base Llama 3.2 3B | Fabricated a Chinese MSS Unit 61398 attribution with a custom "Lyrebird" backdoor. Pure invention, no caveats. |
| **This fine-tune** | "I don't have reliable information on this threat actor. The identifier may be a typo or unrecognized alias…" |

ซึ่งสำหรับ Red Team แล้วเป็นสิ่งที่ยอมรับได้ เพราะจะได้ไม่ทำให้ Red Team สืบสวนผิดทาง

โดยความสามารถนี้สร้างโดยการนำเอา **ตัวอย่างสถานการณ์ที่ไม่แน่นอน 820 รายการที่สร้างโดย Claude Opus 4.7 และกำหนดให้ไม่ใช้แพตเทิร์นเดิมๆ** ซึ่งครอบคลุมตั้งแต่หมายเลข CVE ปลอม, ชื่อกลุ่มภัยคุกคามปลอม, ข้อมูลนำเข้าที่ไม่เพียงพอ, การขอข้อมูลแบบเรียลไทม์, คำถามที่อยู่นอกเหนือขอบเขตความรู้, ไปจนถึงคำสั่งที่กำกวม โดยแต่ละตัวอย่างจะถูกสุ่มผสมรูปแบบประโยคเข้าด้วยกัน

### ข้อจำกัด

นี่คือโมเดลเวอร์ชัน 1 ที่ได้ฝึกไปเพียง 500 จากที่ตั้งใจไว้ 1,500 สเต็ป ด้านล่างนี้เป็นข้อจำกัดที่สังเกตเห็นในระหว่างการทำ smoke tests ผมจึงระบุเอาไว้เพื่อให้ทุกคนที่นำโมเดลนี้ไปประเมิน ได้เข้าใจว่ามีสิ่งใดบ้างที่ยังทำงานได้ไม่สมบูรณ์

1. **การสกัดข้อมูล IOC แบบคำต่อคำยังไม่น่าเชื่อถือ** โมเดลมีการดัดแปลง Domain/URL ที่รับเข้ามาเป็นบางครั้ง แทนที่จะคัดลอกมาแบบเป๊ะๆ สิ่งที่พบคือ: airdrop-update[.]com กลายเป็น airdrop/update[.]com หรือ .com กลายเป็น .cm ปัญหานี้ส่วนหนึ่งมาจากข้อจำกัดของขนาดโมเดล 3B และอีกส่วนหนึ่งมาจากสัดส่วนชุดข้อมูลที่ใช้ฝึก (เทมเพลตมีลักษณะที่ "มีรูปร่างหน้าตาคล้าย IOC" แทนที่จะเป็นการ "คัดลอกมาตรงๆ")
2. **มั่วค่า Hash** ในการทดสอบพรอมต์อันหนึ่ง โมเดลได้สร้างข้อความที่เป็นค่า SHA ขึ้นมาเองโดยที่ไม่มีอยู่ในข้อมูลนำเข้า ในชุดฝึกสอนผมได้สอนให้ยอมรับเรื่องรหัส CVE ปลอมและชื่อกลุ่มผู้โจมตีปลอมไปแล้ว แต่ยังไม่ได้รวมค่า Hash ปลอมเข้าไปด้วย
3. **การวิเคราะห์รหัส CVE แย่ลงเมื่อเทียบกับโมเดลพื้นฐาน** โมเดลระวังตัวเองมากเกินไปกับรหัส CVE ที่มีอยู่จริง (โมเดลจะตอบว่า "ไม่จัดประเภท (Unclassified)" / "ให้ตรวจสอบค่า CVSS เอาเอง" แทนที่จะให้การวิเคราะห์เรื่องการใช้ช่องโหว่นั้นโจมตี) ข้อมูลที่สอนเรื่องความไม่แน่นอนทั้ง 820 รายการรุนแรงเกินไป ทำให้พฤติกรรมปฏิเสธลามไปข้อมูลที่โมเดลรู้จักอยู่แล้วมากเกินไป
4. **การฝึกสอนไม่เสร็จสิ้นตามกำหนดการที่วางไว้** โมเดลถูกฝึกไปเพียงประมาณ 0.2 epochs จากทั้งหมด 102K รายการ ไม่ใช่ 1 epoch ตามที่ตั้งใจไว้ ยังไงก็ตามถึงจะเพิ่มจำนวนสเต็ปการฝึกก็ไม่สามารถแก้ไขปัญหาในข้อ 1-3 ข้างต้นได้ (เพราะปัญหาเเกิดจากสัดส่วนของข้อมูลที่ใช้ฝึก ไม่ใช่ปัญหาเรื่องจำนวนสเต็ป)

---

## 3. การรวบรวมข้อมูล

### ทำไมต้องสร้างชุดข้อมูลเอง
เนื่องจากไม่มีข้อมูลสำเร็จรูป ผมจึงรวบรวม 114,403 รายการ จาก 22 แหล่งที่แตกต่างกันด้วยวิธี:
1. เขียน script เก็บข้อมูลแจ่ละแหล่งโดยใช้ API และบางที่สามารถโหลดได้เลย
2. แปลงข้อมูลดิบเป็น (system / user / assistant)
3. เขียน script ทำความสะอาด, คัดข้อมูลซ้ำ

### เก็บข้อมูลรอบแรก

| Source | What It Is | Records |
|---|---|---|
| NVD/MITRE CVE | คำอธิบายช่องโหว่ (downsampled) | 118,951 → 18,296 |
| Exploit-DB | metadata ของ exploit | 33,976 → 19,199 |
| AlienVault OTX | Threat intelligence pulses | 8,420 → 8,288 |
| HF Fenrir v2.0 | Red team Q&A สร้างด้วย AI (downsampled) | 99,870 → 18,943 |
| HF CTI | บทความข่าวกรองภัยคุกคาม | 7,603 → 7,537 |
| ThreatFox | IOC ของ Malware | 4,487 → 4,366 |
| Telegram channels | CVE alerts, threat intel | 3,539 → 3,331 |
| HF HackerNews | บทสนทนาในชุมชน security | 5,000 → 4,986 |
| Wikipedia Security | บทความแนวคิดด้านความปลอดภัย| 2,862 → 2,858 |
| BleepingComputer | ข่าวความปลอดภัย | 110 → 110 |
| VirusTotal | คอมเมนต์การวิเคราะห์มัลแวร์ | 74 → 43 |

**3 แหล่งที่ถูกตัดทิ้งหลังตรวจสอบ:**
- `hf_phishing_email` — กลายเป็นชุด Enron spam/ham ไม่ใช่เนื้อหา cybersecurity
- `hf_phishing` — 45% เป็น URL เปล่าๆ ไม่มีเนื้อข้อความ
- `security_news` — 91% เป็นบทความซ้ำกับ BleepingComputer

เนื่องจากผมได้พบปัญหาว่าสัดส่วนข้อมูลจาก AI ค่อนข้างเยอะ ~30% ผมจึงได้ลองหาข้อมูลเพิ่ม

### เก็บเพิ่มเติม

| Source | What It Is | Records |
|---|---|---|
| GHSA | คำเตือนช่องโหว่ของ package บน GitHub | 5,800 → 5,480 |
| arXiv cs.CR | งานวิจัยด้าน security เชิงวิชาการ | 5,009 → 5,008 |
| MISP Galaxy | โปรไฟล์กลุ่มผู้โจมตี + มัลแวร์ (Malpedia) | 3,860 → 3,761 |
| Loghub | log ของ SSH/Linux/Apache (3 ประเภท) | 3,461 → 3,223 |
| HF Cyber v1 | Q&A ด้าน security สร้างด้วย AI | 2,410 → 1,889 |
| Atomic Red Team | ขั้นตอนการทดสอบ ATT&CK | 1,753 → 1,500 |
| CISA KEV | ช่องโหว่ที่ยืนยันแล้วว่าถูกโจมตีจริง | 1,587 → 1,396 |
| abuse.ch URLhaus | URL ดาวน์โหลดมัลแวร์ที่ active อยู่ | 1,134 → 1,133 |
| MITRE ATT&CK | เทคนิค, มัลแวร์, กลุ่มภัยคุกคาม (STIX) | 2,298 → 2,212 |
| Mandiant Blog | รายงานการระบุที่มา APT (RSS) | 20 → 20 |
| SANS ISC | รายงานภัยคุกคามรายวัน | 4 → 4 |

### ยอดรวม
- **ข้อมูลดิบทั้งหมด:** 312,228 จาก 22 แหล่ง
- **หลังทำความสะอาด:** 114,403 รายการ

---

### ข้อมูลฝึกให้ปฏิเสธ
เนื่องจากผมไม่อยากให้มันมั่วคำตอบขึ้นมาจึงเพิ่ม **820 ตัวอย่างความไม่แน่นอน** ขึ้นมาด้วย:

| Category | Examples |
|---|---|
| รหัส CVE ปลอม (CVE-9999-XXXXX) | 150 |
| ชื่อกลุ่มผู้โจมตีปลอม | 150 |
| ข้อมูลนำเข้าไม่พอ / ว่างเปล่า | 100 |
| ขอข้อมูลแบบเรียลไทม์ ("ตอนนี้กำลังเกิดอะไร") | 100 |
| ค้นหา hash สุ่ม (ที่ไม่รู้จัก) | 100 |
| คำถามนอกขอบเขตความรู้ | 80 |
| คำถามกำกวม | 80 |
| ขอให้ทำนาย / คาดการณ์ในอนาคต | 60 |

คำตอบแต่ละตัวทำเป็ **สุ่มผสมรูปแบบประโยค**

### ชุดข้อมูลสุดท้าย

| Split | Records |
|---|---|
| Train | 102,962 |
| Validation | 5,674 |
| Test | 5,679 |
| **Total (after final cross-split dedup)** | **114,315** |

### อัตราส่วนของข้อมูล

| Composition | Records | % |
|---|---|---|
| Human-curated / API-sourced | 92,751 | 81.1% |
| AI-generated (HF Fenrir + Cyber v1) | 20,832 | 18.2% |
| Synthetic uncertainty (Claude Opus 4.7) | 820 | 0.7% |

---

## 4. EDA

EDA เต็มพร้อมกราฟ: [`eda.ipynb`](eda.ipynb) กราฟ PNG: [`reports/eda/`](reports/eda/)

### Source Distribution
3 แหล่งใหญ่ที่สุด (Exploit-DB 16.8%, HF Fenrir 16.6%, NVD CVE 16.0%) รวมกันคิดเป็น ~49.3% ของชุดข้อมูล อีก 20 แหล่งที่เหลือมีสัดส่วน 0.0%–7.2% ให้ความครอบคลุมข้ามทั้งข่าวกรองภัยคุกคาม, งานวิจัยเชิงวิชาการ, บทสนทนาในชุมชน, และขั้นตอนของ Red Team

### Real vs AI-Generated
81.1% เป็นแหล่งข้อมูลจากมนุษย์, 18.2% เป็น Q&A ที่ AI สร้าง, 0.7% เป็นตัวอย่างความไม่แน่นอน

### Text Length Distribution
- ความยาว user-message median: **315 ตัวอักษร**
- p95: **1,628 ตัวอักษร**
- p99: **2,294 ตัวอักษร**

### IOC Coverage
- **54,719 รายการ (47.8%)** มี IOC แบบ defanged อย่างน้อย 1 ตัว
- CVE IDs พบบ่อยที่สุด (40,016 รายการ / 35.0%), รองลงมาคือ defanged domains (15,394 / 13.5%) และ URLs (12,624 / 11.0%)
- Defanged IPs (4,416) และ hashes (1,710) พบน้อย

### MITRE ATT&CK Coverage
- **เทคนิคที่แตกต่างกัน:** 858 เทคนิค
- **การกล่าวถึงรวม:** 68,723 ครั้ง (เฉลี่ย 80.1 ครั้ง/เทคนิค)
- ครอบคลุม technique ตลอด phase ตั้งแต่ Reconnaissance ถึง Impact

### Kill Chain Phase Coverage
- **Reconnaissance: 70,129 รายการ (61.3%)** — ครองส่วนใหญ่เพราะเนื้อหา OSINT และ discovery พบบ่อยที่สุดใน threat intel
- **Initial Access: 19,356 (16.9%)** — รองลงมา (phishing, watering hole ฯลฯ)

---

### ผลการฝึก

| Metric | Value |
|---|---|
| Steps trained | 500 จาก 1,500 ที่วางแผน |
| Epochs completed | 0.2035 (~20,953 จาก 102,962 ตัวอย่าง) |
| Train loss | 0.9084 |
| Eval loss | 0.9103 |
| Train token accuracy | 80.4% |
| Eval token accuracy | 80.7% |
| Overfitting | ไม่พบ (eval ≈ train) |

### ผลการ Smoke Test (5 Prompts)

| Prompt | Base Model | Fine-Tune |
|---|---|---|
| IOC Extraction (CobaltStrike C2) | สกัดได้แบบพื้นฐาน | มีโครงสร้างและมี kill chain |
| Threat Actor Profile (SpaceX scenario) | สกัดได้บางส่วน | บางส่วน และมีการดัดแปลง IOC |
| CVE Red Team Assessment (Log4Shell) | วิเคราะห์ได้ในระดับใช้ได้ | ระวังเกินไป — ตอบ "Unclassified" (เป็น regression ที่รู้อยู่แล้ว) |
| Honesty Check: CVE-9999-987654 สมมติ | ปฏิเสธ | ปฏิเสธ |
| Honesty Check: APT-Lyrebird-77 สมมติ | **มั่ว** ระบุที่มาเป็น Chinese MSS + แบ็คดอร์เอง | **ปฏิเสธ** |

---

## 5. อ้างอิง

| Source | URL / Location | License |
|---|---|---|
| NVD/MITRE CVE | https://nvd.nist.gov | Public Domain |
| Exploit-DB | https://www.exploit-db.com | Offensive Security |
| AlienVault OTX | https://otx.alienvault.com | Community |
| HF Fenrir v2.0 | HuggingFace: AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0 | See dataset card |
| HF CTI | HuggingFace: mrmoor/cyber-threat-intelligence | See dataset card |
| GHSA | https://github.com/advisories | GitHub ToS |
| arXiv cs.CR | https://arxiv.org | arXiv license |
| HF HackerNews | HuggingFace: open-index/hacker-news | See dataset card |
| ThreatFox | https://threatfox.abuse.ch | CC0 |
| MISP Galaxy | https://github.com/MISP/misp-galaxy | Apache 2.0 |
| Telegram channels | @cveNotify, @TheDarkWebInformer, @secharvest, etc. | Public channel content |
| Loghub | https://github.com/logpai/loghub | MIT |
| Wikipedia Security | HuggingFace: wikimedia/wikipedia | CC BY-SA 4.0 |
| MITRE ATT&CK | https://attack.mitre.org | Apache 2.0 |
| HF Cyber v1 | HuggingFace: AlicanKiraz0/Cybersecurity-Dataset-v1 | See dataset card |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | MIT |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Public Domain |
| abuse.ch URLhaus | https://urlhaus.abuse.ch | CC0 |
| BleepingComputer | https://www.bleepingcomputer.com | Fair use / RSS |
| VirusTotal | https://www.virustotal.com | VirusTotal Terms |
| Mandiant Blog | https://www.mandiant.com/resources/blog | Fair use / RSS |
| SANS ISC | https://isc.sans.edu | Fair use / RSS |
