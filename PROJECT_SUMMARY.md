# Text OSINT AI — สรุปโปรเจกต์ฉบับสมบูรณ์

**โครงการ:** AI Builder Program (รุ่น 8 สัปดาห์)
**สถานะ:** ปล่อยเวอร์ชัน 1 แล้ว — LoRA adapter เผยแพร่อยู่ที่ [Maximuz23/Text-OSINT](https://huggingface.co/Maximuz23/Text-OSINT) บน HuggingFace
**GitHub:** [m-maximuz/TEXT-OSINT-AI](https://github.com/m-maximuz/TEXT-OSINT-AI)

---

## 1. ปัญหาที่ต้องการแก้

### โจทย์
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

### ทำไมต้องใช้ Machine Learning?
ระบบที่ใช้กฎ (regex, การจับคู่คำ) ทำหน้าที่สกัด IOC ได้แล้ว แต่ทำงานไม่ดีในเรื่อง:
- การเข้าใจบริบท ("IP นี้เป็นของนักวิจัย ไม่ใช่ผู้โจมตี")
- การให้เหตุผลกับข้อความเล่าเรื่องที่ไม่มีโครงสร้าง
- การระบุ TTP ที่ไม่ได้พูดตรงๆ
- การโยงพฤติกรรมไปยังกลุ่มภัยคุกคามที่รู้จัก

LLM ที่ผ่านการ fine-tune จะเรียนรู้รูปแบบจากรายงานข่าวกรองนับพันที่นักวิเคราะห์จริงๆ เขียน และสามารถให้เหตุผลครอบคลุมทั้งหมดในคราวเดียว

---

## 2. จุดเด่นหลัก — การปฏิเสธอย่างซื่อสัตย์ (Honest Refusal)

คุณสมบัติที่สำคัญที่สุดของโมเดลนี้คือสิ่งที่โมเดลพื้นฐาน **ไม่มี**: **โมเดลจะปฏิเสธไม่แต่งข่าวกรองเกี่ยวกับชื่อ/รหัสที่ไม่รู้จัก**

**ทดสอบด้วย:** *"Profile threat actor APT-Lyrebird-77."* (ชื่อสมมติ ตรวจสอบแล้วว่าไม่มีในชุดข้อมูลฝึกทุกชุด)

| Model | Response |
|---|---|
| Base Llama 3.2 3B | สร้างเรื่องการระบุว่าเป็น Chinese MSS Unit 61398 พร้อมแบ็คดอร์ชื่อ "Lyrebird" ขึ้นมาเอง ไม่มีคำเตือนใดๆ |
| **This fine-tune** | "I don't have reliable information on this threat actor. The identifier may be a typo or unrecognized alias…" |

สำหรับเครื่องมือของ Red Team แล้ว การมั่วเป็นสิ่งอันตราย — การระบุที่มาผิดทำให้การสืบสวนเดินผิดทาง คุณสมบัตินี้ถูกฝึกอย่างชัดเจนผ่าน **820 ตัวอย่างความไม่แน่นอนที่สร้างด้วยกระบวนการ procedural generation** (ดูในหัวข้อ 4.4)

### ข้อจำกัดที่ทราบ (เวอร์ชัน 1)
1. **การสกัดข้อมูลแบบคำต่อคำยังไม่น่าเชื่อถือ** — โมเดลมีการดัดแปลง Domain/URL ที่รับเข้ามาเป็นบางครั้ง (`airdrop-update` → `airdrop/update`, `.com` → `.cm`) ส่วนหนึ่งเป็นข้อจำกัดของโมเดลขนาด 3B
2. **มั่วค่า Hash** — ในการทดสอบหนึ่ง โมเดลสร้างค่า SHA ขึ้นมาเองที่ไม่มีในข้อมูลนำเข้า การฝึกเรื่องความซื่อสัตย์ครอบคลุม CVE ปลอมและชื่อกลุ่มผู้โจมตีปลอม แต่ยังไม่รวม Hash ปลอม — เป็นช่องว่างในการครอบคลุม
3. **การวิเคราะห์ CVE แย่ลงเทียบกับโมเดลพื้นฐาน** — ข้อมูลเรื่องความไม่แน่นอนที่ฝึกเข้าไปทำให้โมเดลระวังตัวมากเกินไปกับ CVE จริง (ตอบว่า "Unclassified" / "verify CVSS" แทนที่จะให้การวิเคราะห์) — เป็นปัญหาเรื่องสัดส่วนข้อมูล
4. **ฝึกไป 500 จาก 1,500 สเต็ปที่วางแผนไว้** — ค่า loss กำลังลดลงน้อยมาก จึงปล่อยออกมาเพื่อทดสอบคุณภาพก่อนใช้โควต้า GPU เพิ่ม สามข้อจำกัดข้างต้นเป็นปัญหาสัดส่วนข้อมูล ไม่ใช่ปัญหาที่แก้ได้ด้วยการเพิ่มสเต็ป

---

## 3. การรวบรวมข้อมูล (Data Collection)

### ทำไมต้องสร้างชุดข้อมูลเอง
ไม่มีชุดข้อมูลสำเร็จรูปสำหรับ "Text OSINT สำหรับ Red Team" เราจึงรวบรวม 114,403 รายการ จาก 22 แหล่งที่แตกต่างกันด้วยวิธี:
1. เขียน script เก็บข้อมูลรายแหล่ง โดยแต่ละแหล่งใช้ API, วิธี authentication, และรูปแบบข้อมูลที่ต่างกัน
2. แปลงข้อมูลข่าวกรองดิบเป็นรูปแบบ instruction-tuning (system / user / assistant)
3. สร้าง logic การทำความสะอาด, การคัดข้อมูลซ้ำ, และการสร้างคำตอบเอง

### Phase 1 — การเก็บข้อมูลรอบแรก

| Source | What It Is | Records |
|---|---|---|
| NVD/MITRE CVE | คำอธิบายช่องโหว่ 118K รายการ (downsampled) | 118,951 → 18,296 |
| Exploit-DB | metadata ของ exploit สาธารณะ 34K รายการ | 33,976 → 19,199 |
| AlienVault OTX | Threat intelligence pulses | 8,420 → 8,288 |
| HF Fenrir v2.0 | Red team Q&A สร้างด้วย AI (downsampled) | 99,870 → 18,943 |
| HF CTI | บทความข่าวกรองภัยคุกคามของจริง | 7,603 → 7,537 |
| ThreatFox | IOC ของ Malware | 4,487 → 4,366 |
| Telegram channels | CVE alerts, threat intel แบบเรียลไทม์ | 3,539 → 3,331 |
| HF HackerNews | บทสนทนาในชุมชน security (กรองแล้ว) | 5,000 → 4,986 |
| Wikipedia Security | บทความแนวคิดด้านความปลอดภัย (กรองแล้ว) | 2,862 → 2,858 |
| BleepingComputer | ข่าวความปลอดภัย (RSS) | 110 → 110 |
| VirusTotal | คอมเมนต์การวิเคราะห์มัลแวร์ | 74 → 43 |

**3 แหล่งที่ถูกตัดทิ้งหลังตรวจสอบ:**
- `hf_phishing_email` — กลายเป็นชุด Enron spam/ham ไม่ใช่เนื้อหา cybersecurity
- `hf_phishing` — 45% เป็น URL เปล่าๆ ไม่มีเนื้อข้อความ
- `security_news` — 91% เป็นบทความซ้ำกับ BleepingComputer

### Phase 2 — เก็บเพิ่มเติม (เพื่อลดสัดส่วนข้อมูล AI และเพิ่มข้อมูลจริง)

| Source | What It Is | Records |
|---|---|---|
| GHSA | คำเตือนช่องโหว่ของ package บน GitHub | 5,800 → 5,480 |
| arXiv cs.CR | งานวิจัยด้าน security เชิงวิชาการ | 5,009 → 5,008 |
| MISP Galaxy | โปรไฟล์กลุ่มผู้โจมตี + มัลแวร์ (Malpedia) | 3,860 → 3,761 |
| Loghub | log จริงของ SSH/Linux/Apache (3 ประเภท) | 3,461 → 3,223 |
| HF Cyber v1 | Q&A ด้าน security สร้างด้วย AI | 2,410 → 1,889 |
| Atomic Red Team | ขั้นตอนการทดสอบ ATT&CK ที่เขียนโดยมนุษย์ | 1,753 → 1,500 |
| CISA KEV | ช่องโหว่ที่ยืนยันแล้วว่าถูกโจมตีจริง | 1,587 → 1,396 |
| abuse.ch URLhaus | URL ดาวน์โหลดมัลแวร์ที่ active อยู่ | 1,134 → 1,133 |
| MITRE ATT&CK | เทคนิค, มัลแวร์, กลุ่มภัยคุกคาม (STIX) | 2,298 → 2,212 |
| Mandiant Blog | รายงานการระบุที่มา APT (RSS) | 20 → 20 |
| SANS ISC | รายงานภัยคุกคามรายวัน | 4 → 4 |

### ยอดรวมดิบ
- **รายการดิบทั้งหมด:** 312,228 จาก 22 แหล่ง
- **หลัง pipeline ทำความสะอาดครบทุกขั้น:** 114,403 รายการ

---

## 4. การทำความสะอาดข้อมูล (Data Cleaning)

### ปัญหาที่พบและวิธีแก้

| Problem | Solution |
|---|---|
| HTML entities (`&amp;`, `&#x27;`) | `html.unescape()` |
| BBCode tags (`[b]`, `[url]`) | ลบด้วย Regex |
| Markdown links (`[text](url)`) | แกะเป็นข้อความปกติ |
| URL/IP สดที่อาจอันตราย | Defang: `http://` → `hxxp://`, `.com` → `[.]com` |
| รายการสั้นเกินไป (< 30 ตัวอักษร) | กรองทิ้ง |
| CVE ที่ถูกปฏิเสธ | กรองรายการที่ขึ้นต้นด้วย "REJECTED REASON:" |
| รายการซ้ำกันแบบเป๊ะ | คัดซ้ำด้วย MD5 hash |
| รายการที่คล้ายกัน | MinHash LSH คัดซ้ำแบบ fuzzy ที่ความคล้าย 80% |
| รายการที่ถูกตัดกลางคำ/กลางประโยค | ลบรายการที่ถูกตัด 1,200 รายการ |
| คำปฏิเสธ AI แบบทั่วไป ("As an AI…") | ลบรายการคำปฏิเสธ 194 รายการ |
| ข้อมูลซ้ำข้ามชุด train/valid/test | คัดซ้ำ prompt ข้ามทุก split |

### การคัดซ้ำข้ามชุด (Cross-Split Deduplication)
พบรายการ 28 รายการที่มี user prompt เหมือนกันใน train และ valid และ 21 รายการใน train และ test (จาก Q&A คู่ขนานของ HF Fenrir) แก้ไขจน **ไม่มีข้อมูลรั่วข้ามชุด** — ชุดทดสอบไม่เคยถูกเห็นในตอนฝึก

### Format สำหรับ Instruction-Tuning
รายการดิบทุกรายการถูกแปลงเป็นการสนทนาสำหรับฝึก:
```json
{
  "messages": [
    {"role": "system",    "content": "You are an expert cybersecurity analyst..."},
    {"role": "user",      "content": "Analyze this CVE from a red team offensive perspective: [real CVE text]"},
    {"role": "assistant", "content": "Vulnerability: CVE-2021-44228\nVulnerability Class: RCE\nAttack Vector: Network/Remote — unauthenticated..."}
  ],
  "source": "cve"
}
```

มีเทมเพลตคำตอบเฉพาะทาง 12 แบบ แยกตามประเภทแหล่งข้อมูล:
- CVE → การประเมินช่องโหว่ + คำแนะนำ recon pivot
- MITRE ATT&CK → จับคู่ TTP + การประยุกต์ใช้สำหรับ Red Team
- Logs → ปะติดปะต่อรูปแบบการโจมตี + ระบุ kill chain phase
- OTX → โปรไฟล์กลุ่มผู้โจมตี + สกัด IOC
- Atomic Red Team → บริบทการรันเทคนิค + รอยที่ระบบตรวจจับจะเห็น
- arXiv → ผลการวิจัย + นัยยะเชิงรุก
- ฯลฯ

### ข้อมูลฝึกความซื่อสัตย์ / Uncertainty
หากไม่สอนให้ชัดเจน โมเดลจะมั่วคำตอบสำหรับชื่อ/รหัสที่ไม่รู้จัก เราจึงเพิ่ม **820 ตัวอย่างความไม่แน่นอนที่สร้างด้วย procedural generation** ครอบคลุม:

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

คำตอบแต่ละตัวถูกสร้างด้วยการ **สุ่มผสมรูปแบบประโยค** (ไม่ใช่เทมเพลตตายตัว) เพื่อให้โมเดลเรียนรู้ *พฤติกรรม* ของการยอมรับความไม่แน่นอน ไม่ใช่ข้อความปฏิเสธแบบเฉพาะตัว

### ชุดข้อมูลสุดท้าย

| Split | Records |
|---|---|
| Train | 102,962 |
| Validation | 5,674 |
| Test | 5,679 |
| **Total (after final cross-split dedup)** | **114,315** |

(ส่วนต่าง 88 รายการระหว่าง 114,403 ของชุดทำความสะอาดกับ 114,315 ของ split สุดท้าย มาจากการคัดข้อมูลซ้ำข้ามชุด train/valid/test รอบสุดท้าย)

| Composition | Records | % |
|---|---|---|
| Human-curated / API-sourced | 92,751 | 81.1% |
| AI-generated (HF Fenrir + Cyber v1) | 20,832 | 18.2% |
| Synthetic uncertainty (Claude Opus 4.7) | 820 | 0.7% |
| Cross-split leakage | 0 | 0% |
| Truncated records | 0 | 0% |
| Generic AI disclaimers | 0 | 0% |

---

## 5. การวิเคราะห์ข้อมูลเชิงสำรวจ (EDA)

EDA ฉบับเต็มพร้อมกราฟ inline: [`eda.ipynb`](eda.ipynb) ส่วนกราฟ PNG แบบ standalone: [`reports/eda/`](reports/eda/)

### Source Distribution
3 แหล่งใหญ่ที่สุด (Exploit-DB 16.8%, HF Fenrir 16.6%, NVD CVE 16.0%) รวมกันคิดเป็น ~49.3% ของชุดข้อมูล อีก 20 แหล่งที่เหลือมีสัดส่วน 0.0%–7.2% ให้ความครอบคลุมข้ามทั้งข่าวกรองภัยคุกคาม, งานวิจัยเชิงวิชาการ, บทสนทนาในชุมชน, และขั้นตอนของ Red Team

### Real vs AI-Generated
81.1% เป็นแหล่งข้อมูลจากมนุษย์/API ที่น่าเชื่อถือ, 18.2% เป็น Q&A ที่ AI สร้าง, 0.7% เป็นตัวอย่างความไม่แน่นอนสังเคราะห์ ส่วน AI-generated ให้ format Q&A แบบมีโครงสร้างและความครอบคลุม ส่วน Human-curated เป็นกระดูกสันหลังที่ให้ความถูกต้องของข้อมูลจริง

### Text Length Distribution
- ความยาว user-message median: **315 ตัวอักษร**
- p95: **1,628 ตัวอักษร**
- p99: **2,294 ตัวอักษร**

ตัวเลขนี้นำไปสู่การเลือก `max_seq_length = 1024` — ครอบคลุมข้อมูลฝึกส่วนใหญ่ขณะที่ยังคุมต้นทุน attention ได้ (O(L²) ดังนั้น 1024 vs 2048 เร็วกว่าประมาณ 4 เท่า)

### IOC Coverage
- **54,719 รายการ (47.8%)** มี IOC แบบ defanged อย่างน้อย 1 ตัว
- CVE IDs พบบ่อยที่สุด (40,016 รายการ / 35.0%), รองลงมาคือ defanged domains (15,394 / 13.5%) และ URLs (12,624 / 11.0%)
- Defanged IPs (4,416) และ hashes (1,710) พบน้อย — ช่องว่างเหล่านี้สอดคล้องกับปัญหาการมั่ว hash ที่พบในเวอร์ชัน 1

### MITRE ATT&CK Coverage
- **เทคนิคที่แตกต่างกัน:** 858 เทคนิค
- **การกล่าวถึงรวม:** 68,723 ครั้ง (เฉลี่ย 80.1 ครั้ง/เทคนิค)
- ครอบคลุม technique ตลอด phase ตั้งแต่ Reconnaissance ถึง Impact

### Kill Chain Phase Coverage
- **Reconnaissance: 70,129 รายการ (61.3%)** — ครองส่วนใหญ่เพราะเนื้อหา OSINT และ discovery พบบ่อยที่สุดใน threat intel สาธารณะ
- **Initial Access: 19,356 (16.9%)** — รองลงมา (phishing, watering hole ฯลฯ)
- ครอบคลุมครบทั้ง 10 phase; Impact (1,608 รายการ) เป็น phase ที่น้อยที่สุด

---

## 6. โมเดล — Fine-Tuning Llama 3.2 3B

### ทำไมเลือก Llama 3.2 3B
แผนเดิมคือ Llama 3.1 8B แต่หลังจากดีบักนานมาก (รัน Kaggle 18 ครั้ง) ก็ตัดสินใจเปลี่ยนมาเป็น **Llama 3.2 3B** ด้วยเหตุผล:
- 8B + plain transformers + PEFT ใส่ลง T4 เดียวพร้อม LoRA ที่มีความจุพอใช้ไม่ได้ (ต้องลด sequence length และ rank อย่างรุนแรงจนเสียจุดประสงค์)
- 3.2 3B กิน VRAM ~2.1 GB เทียบกับ ~5.3 GB ของ 8B — พอดีกับ T4 เดียวพร้อม config ที่เหมาะสม
- สถาปัตยกรรมเหมือนกัน (LlamaForCausalLM), target modules ของ LoRA เหมือนกัน, chat template เหมือนกัน
- บนชุดข้อมูล OSINT เฉพาะทาง 102K รายการ โมเดล 3B ที่ฝึกดีๆ มีประโยชน์มากกว่าโมเดล 8B ที่ฝึกไม่ดี

ข้อแลก: 3B ทำงานทั่วไปได้ด้อยกว่า การ retrain บน 8B หรือใหญ่กว่านั้นเป็นงานหลังจบโครงการเมื่องบฮาร์ดแวร์เพียงพอ

### ทำไม QLoRA
การ Fine-tune โมเดล 3B แบบเต็มยังคงใช้ GPU memory และเวลามาก QLoRA:
1. โหลด base model แบบ **4-bit quantization** (ลด memory 8 เท่า)
2. Freeze weight เดิมทั้งหมด
3. เพิ่ม LoRA adapter matrix ตัวเล็กๆ ที่ฝึกได้ (~1.5% ของพารามิเตอร์)
4. ฝึกเฉพาะ adapter — เร็ว, ถูก, และ reversible

### Training Configuration

| Setting | Value | Reason |
|---|---|---|
| Base model | `unsloth/Llama-3.2-3B-Instruct-bnb-4bit` | quantize มาแล้ว ไม่ติด license gate |
| LoRA rank (r) | 32 | sweet spot มาตรฐานสำหรับ 3B |
| LoRA alpha | 32 | alpha = r → scaling = 1.0 |
| Trainable params | 48.6M (1.5% ของ 3.21B) | ความจุ adapter เพียงพอ |
| Max seq length | 1,024 | p99 ของข้อมูลฝึกประมาณ 1,080 tokens |
| Batch size | 1 (grad accum 16) | trl 0.18.2 มีบั๊กตอน batch > 1 |
| Effective batch | 16 | ผ่าน gradient accumulation |
| Learning rate | 1e-4 | มาตรฐานสำหรับ QLoRA |
| LR scheduler | Cosine + 5% warmup | decay ราบเรียบ |
| Weight decay | 0.01 | กัน overfit |
| Packing | True | บีบตัวอย่างสั้นเข้า sequence 1024 token (throughput ~2.5×) |
| Max steps | 1,500 (planned) | ฝึกจริง 500 — ดูในส่วนผล |
| Optimizer | paged_adamw_8bit | AdamW ประหยัด memory |
| Hardware | Kaggle T4 (single GPU, 16 GB) | tier ฟรี |

### ปัญหาด้าน Environment ที่ต้องจัดการ (เรียนรู้จากการล้มมาแล้ว)
- **`CUDA_VISIBLE_DEVICES=0` ก่อน import torch** — Kaggle T4×2 จะถูก HF Trainer auto-wrap เป็น DataParallel ทำให้ CUBLAS OOM ตอน eval ซ่อน GPU 1 ทิ้งไปเลย
- **`gradient_checkpointing_kwargs={"use_reentrant": False}`** — PEFT + 4-bit + grad-checkpointing ทำให้ gradient ของ LoRA แตกแบบเงียบๆ ถ้าใช้ `use_reentrant=True`
- **`dataset_num_proc=1`** — multi-process dataset prep deadlock กับ CUDA state ของ bnb-4bit
- **`load_best_model_at_end=True`**: eval รัน *ก่อน* save ในบล็อกเดียวกัน — ถ้า eval crash แปลว่าไม่มี checkpoint เลย ให้ subsample ชุด eval และทดสอบด้วย sanity run ก่อนทุ่ม 10+ ชั่วโมง

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

Loss ลดจาก 2.77 (สุ่ม) มาเป็น 0.91 — **ลดลง 3 เท่า** ค่า gradient norm 0.24–0.45 (สุขภาพดี) ระหว่างสเต็ป 400–500 loss ลดเพียง 2% บ่งบอกถึง diminishing returns จึง ship ที่สเต็ป 500 เพื่อทดสอบคุณภาพก่อนใช้โควต้า Kaggle เพิ่ม

### ผลการ Smoke Test (5 Prompts)

| Prompt | Base Model | Fine-Tune |
|---|---|---|
| IOC Extraction (CobaltStrike C2) | สกัดได้แบบพื้นฐาน | output แบบ Red Team มีโครงสร้าง พร้อมกรอบ kill chain |
| Threat Actor Profile (SpaceX scenario) | สกัดได้บางส่วน | บางส่วน — พบการดัดแปลง IOC |
| CVE Red Team Assessment (Log4Shell) | วิเคราะห์ได้ในระดับใช้ได้ | ระวังเกินไป — ตอบ "Unclassified" (regression ที่รู้แล้ว) |
| Honesty Check: CVE-9999-987654 สมมติ | ปฏิเสธ (RLHF จัดการได้อยู่แล้ว) | ปฏิเสธอย่างชัดเจน |
| Honesty Check: APT-Lyrebird-77 สมมติ | **มั่ว** ระบุที่มาเป็น Chinese MSS + แบ็คดอร์เอง | **ปฏิเสธ** อย่างชัดเจน — จุดเด่นหลัก |

---

## 7. การ Deploy

### Artifacts ที่ Ship สำหรับ v1

| Artifact | Location |
|---|---|
| LoRA adapter | [Maximuz23/Text-OSINT](https://huggingface.co/Maximuz23/Text-OSINT) (HuggingFace, private) |
| Local backup | `~/osint-project/checkpoint-500/` |
| Training notebook | `osint-ai.ipynb` (รันบน Kaggle T4) |
| Inference + smoke test | `ai-test.ipynb` (รันบน Kaggle T4) |
| GitHub repo | [m-maximuz/TEXT-OSINT-AI](https://github.com/m-maximuz/TEXT-OSINT-AI) |

### วิธีโหลด Adapter

```python
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

BASE = "unsloth/Llama-3.2-3B-Instruct-bnb-4bit"
ADAPTER = "Maximuz23/Text-OSINT"  # requires HF auth (private)

tokenizer = AutoTokenizer.from_pretrained(BASE)
model = AutoModelForCausalLM.from_pretrained(BASE, device_map={"": 0}, torch_dtype=torch.float16)
model = PeftModel.from_pretrained(model, ADAPTER)

messages = [
    {"role": "system", "content": "You are an expert cybersecurity analyst..."},
    {"role": "user", "content": "Profile threat actor APT-Lyrebird-77."},
]
inputs = tokenizer.apply_chat_template(messages, return_tensors="pt", add_generation_prompt=True).to(model.device)
out = model.generate(inputs, max_new_tokens=512, repetition_penalty=1.05, no_repeat_ngram_size=10)
print(tokenizer.decode(out[0], skip_special_tokens=True))
```

### แผน: Live OSINT Layer (Phase 7)
โมเดล v1 ทำงานกับข้อความ static เท่านั้น ระบบ production จะเพิ่ม **Live Data Router** ที่ query API จริงและส่งผลกลับเป็นบริบทก่อนเรียกโมเดล:

| Data type | API ที่วางแผนจะต่อ |
|---|---|
| Threat intel | AlienVault OTX, NVD, VirusTotal, AbuseIPDB, Hybrid Analysis, abuse.ch |
| Target recon | Shodan, Censys, IPinfo, crt.sh, WHOIS, GitHub |
| No-key sources | crt.sh, WHOIS |

Demo สุดท้าย: Streamlit UI — ผู้ใช้แปะ threat artifact (IP, CVE, IOC, รายงานภัยคุกคาม), router จะ query API ที่เกี่ยวข้อง, โมเดลรับ artifact + บริบทสด, ส่งคืนเป็นรายงาน Red Team OSINT ที่มีโครงสร้าง

---

## 8. แหล่งข้อมูล (Data Sources)

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
