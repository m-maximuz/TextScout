# Text-OSINT-AI

โมเดล Llama 3.2 3B ที่ถูก fine-tune มาเพื่อทำงาน Text OSINT สำหรับ Red Team Analysts โดยตั้งเป้าไว้ว่าให้สามารถ**ปฏิเสธในสิ่งที่ตัวเองไม่มีข้อมูลได้**

[`Maximuz23/Text-OSINT`](https://huggingface.co/Maximuz23/Text-OSINT)

---

## จุดที่แตกต่างจากโมเดลตัวอื่น

ทดลองถามชื่อ threat actor ปลอม (ชื่อสมมุติขึ้นมา และตรวจแล้วว่าไม่มีในข้อมูลฝึกฝน):

| Prompt | Base Llama 3.2 3B | Fine-tune |
|---|---|---|
| `"Profile threat actor APT-Lyrebird-77."` | มั่วเรื่องขึ้นมา บอกเป้าหมาย, ประเทศที่มา, malware | *"I don't have information on APT-Lyrebird-77. Could be a typo, or fictional."* |
| `"Profile threat actor APT-Stoneraven-42."`| มั่วเรื่อง และให้เป็น malware ชื่อ `Stoneraven-42-0.9.1` | *"I don't have information on APT-Stoneraven-42."* |

สำหรับ Red Team ความสามารถนี้สำคัญ เพราะถ้าโมเดลมั่วจะทำให้ทีมจะสืบสวนไปผิดทางทำให้เสียเวลา

ทำโดยใส่ prompt ที่ไม่แน่นอน **820 records** ที่สร้างโดย Claude Opus 4.7 (CVE ปลอม, actor ปลอม, ข้อมูลไม่พอ, ขอข้อมูลแบบ real-time, นอกขอบเขต, ฯลฯ)

---

## รายละเอียดแบบสรุป

- **เวอร์ชันปัจจุบัน:** v2.3
- **Training data:** 41,371 records จาก 10 sources (จาก v1 ที่มี 114K ผมได้ตัด source ออกไป 13 sources)
- **Loss:** validation 0.7688
- **Smoke test (7 prompts):** v2.3 ชนะ 4, base ชนะ 2, เสมอ 1
- **ข้อจำกัดที่ยังเหลือ:** มีการแต่งเติมข้อมูลเข้าไป เมื่อเจอ prompt ที่ไม่มีโครงสร้าง

**รายละเอียดเต็มของโปรเจค** ดูที่ [`PROJECT_SUMMARY.md`](PROJECT_SUMMARY.md)

**EDA แบบกราฟ** ดูที่ [`eda.ipynb`](eda.ipynb) และ [`reports/eda/`](reports/eda/)

---

## License

- **Code & model**: BigScience Open RAIL-M — see [`LICENSE`](LICENSE). Open use, subject to the Attachment A use restrictions (no illegal, harmful, or rights-violating use).

## จุดประสงค์การใช้งาน

สำหรับ Red Team ที่**ได้รับอนุญาต**เท่านั้น ห้ามใช้ในการพุ่งเป้าโจมตีที่ไม่ได้รับอนุญาตหรือใช้ในทางที่มุ่งร้าย
