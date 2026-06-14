# TextScout

โมเดล Llama 3.2 3B ที่ถูก fine-tune มาเพื่อทำงาน Text OSINT สำหรับ Red Team Analysts จุดเด่นคือ**ปฏิเสธในสิ่งที่ตัวเองไม่มีข้อมูล**

- Model: [`Maximuz23/Text-OSINT`](https://huggingface.co/Maximuz23/Text-OSINT)
- Demo: [TextScout](https://maximuz23-textscout.hf.space)

---

## รายละเอียดแบบสรุป

- **เวอร์ชันปัจจุบัน:** v3
- **Training data:** 16,399 records จาก 13 sources (~96% real open-source / ~4% honesty signal)
- **ผลทดสอบ (base → fine-tune, test 700 records + probe 80):**

| Metric | Base | Fine-tune |
|---|---:|---:|
| Honesty F1 (ปฏิเสธของปลอม) | 0.62 | **0.99** |
| NER F1 | 0.60 | **0.88** |
| Hallucination (ยิ่งต่ำยิ่งดี) | 0.24 | **0.09** |

- per-category (fine-tune): fake_cve 1.00 / fake_actor 0.95 / real_actor 1.00 / real_cve 1.00
- **ข้อจำกัดที่ยังเหลือ:** ยังมีการมั่วอยู่เล็กน้อยมากๆ, BERTScore/ROUGE-L ที่สูงมาจากการจำ format บางส่วน

**รายละเอียดเต็มของโปรเจค** ดูที่ [`PROJECT_SUMMARY.md`](PROJECT_SUMMARY.md)

**EDA แบบกราฟ** ดูที่ [`eda.ipynb`](eda.ipynb) และ [`reports/eda/`](reports/eda/)

---

## License

- **Code & model**: BigScience Open RAIL-M — see [`LICENSE`](LICENSE). Open use, subject to the Attachment A use restrictions (no illegal, harmful, or rights-violating use).

## จุดประสงค์การใช้งาน

สำหรับ Red Team ที่**ได้รับอนุญาต**เท่านั้น ห้ามใช้ในการพุ่งเป้าโจมตีที่ไม่ได้รับอนุญาตหรือใช้ในทางที่มุ่งร้าย
