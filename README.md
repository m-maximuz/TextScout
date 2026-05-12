# Text-OSINT-AI

A fine-tuned Llama 3.2 3B for Text OSINT — IOC extraction, threat actor profiling, and **honest refusal of fictional identifiers**. Built for red team analysts who need a tool that admits uncertainty instead of fabricating impressive-looking intelligence.

**Model:** [`Maximuz23/Text-OSINT`](https://huggingface.co/Maximuz23/Text-OSINT) (LoRA adapter on `unsloth/Llama-3.2-3B-Instruct-bnb-4bit`)
**Status:** v1 proof-of-concept. Trained on 102,962 records. See [Known Limitations](#known-limitations) below — this is not yet a production tool.

---

## The Differentiator: Honest Refusal

The single most important property of this model is that it **refuses to invent intelligence about unknown identifiers** — and the base model does not.

**Test prompt:** *"Profile threat actor APT-Lyrebird-77."* (a fictional name, verified absent from training data)

| Model | Output |
|---|---|
| Base Llama 3.2 3B | Fabricated a Chinese MSS Unit 61398 attribution with a custom "Lyrebird" backdoor. Pure invention, no caveats. |
| **This fine-tune** | "I don't have reliable information on this threat actor. The identifier may be a typo or unrecognized alias…" |

For a red team tool, the second behavior is the only acceptable one. False attribution sends investigations the wrong way.

This was trained explicitly via **780 procedurally-generated uncertainty examples** covering fake CVE numbers, fake threat actor names, insufficient input, live data requests, out-of-domain questions, and ambiguous queries — each with randomized phrase combinations so the model learns the *behavior*, not specific refusal text.

---

## Known Limitations

This is a v1 trained to step 500 of an intended 1,500 (loss curve was flattening; shipped to test what we had). The limitations below are honest, observed in smoke tests, and listed deliberately so anyone evaluating this model understands what does not yet work.

1. **Verbatim IOC extraction is unreliable.** The model occasionally mutates input domains/URLs rather than copying exactly. Observed: `airdrop-update[.]com` → `airdrop/update[.]com`, `.com` → `.cm`. Partly a 3B-model-size limitation, partly a training-data-mix issue (templates generated "IOC-shaped" rather than "exact copy" outputs).
2. **Hash fabrication observed.** On one smoke prompt the model invented a SHA-like string not present in input. Uncertainty training covered fake CVEs and fake actor names but did not include fake hashes — coverage gap.
3. **CVE analysis regressed vs the base model.** The model over-hedges on real CVEs (says "Unclassified" / "verify CVSS" instead of giving specific exploitation analysis). The 780 uncertainty records over-shot — refusal behavior generalized too aggressively to known identifiers.
4. **Training did not complete the planned schedule.** ~0.2 epochs over 102K examples, not the intended 1 epoch. More steps wouldn't fix points 1–3 above (those are data-mix issues, not step-count issues).

The v1 is shipped as a checkpoint to validate the honesty property — it is not yet positioned as a general-purpose OSINT assistant.

---

## Quickstart

```python
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

BASE = "unsloth/Llama-3.2-3B-Instruct-bnb-4bit"
ADAPTER = "Maximuz23/Text-OSINT"  # private — requires HF auth

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

Sampling settings `repetition_penalty=1.05` and `no_repeat_ngram_size=10` were tuned to suppress a repetition pathology at low temperatures without mangling defanged IOCs (smaller `no_repeat_ngram_size` truncated IPs like `139[.]59[.]226[.]78` → `139[.]`).

---

## Approach

| Component | Choice |
|---|---|
| Base model | Llama 3.2 3B Instruct (4-bit, via Unsloth's pre-quantized public republish) |
| Method | QLoRA — frozen base + LoRA adapters |
| LoRA rank / alpha | 32 / 32 |
| Target modules | `q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj` |
| Trainable params | 48.6M (1.5% of 3.21B base) |
| Max sequence length | 1024 (p99 of training data ≈ 1080 tokens) |
| Effective batch size | 16 (per-device 1, grad accum 16) |
| Hardware | Kaggle T4 (free tier, single GPU) |
| Trained steps | 500 of 1,500 planned |
| Train / eval loss | 0.9084 / 0.9102 (no overfitting) |

The 8B base was dropped early. On a single free T4 with plain transformers + PEFT (Unsloth dropped after compatibility issues), 8B did not fit with meaningful LoRA capacity. 3B specialized on 102K narrow OSINT records produces an adequate proof-of-concept for the honesty property; an 8B retrain on rented hardware is post-program work.

---

## Dataset

102,962 train / 5,720 valid / 5,729 test (zero cross-split leakage after dedup). Records were assembled from 22 sources covering threat intel, vulnerability databases, red team procedures, security discourse, and synthetic uncertainty examples.

| Source | Records (cleaned) |
|---|---:|
| Exploit-DB | 19,199 |
| HF Fenrir v2.0 (downsampled) | 18,895 |
| NVD/MITRE CVE (downsampled) | 18,326 |
| AlienVault OTX | 8,288 |
| HF CTI (mrmoor) | 7,537 |
| GitHub Security Advisories | 5,728 |
| arXiv cs.CR | 5,008 |
| HF Hacker News (security subset) | 4,986 |
| ThreatFox | 4,366 |
| MISP Galaxy | 3,761 |
| Telegram security channels | 3,331 |
| Loghub (SSH/Linux/Apache) | 3,223 |
| Wikipedia (security articles) | 2,858 |
| MITRE ATT&CK | 2,212 |
| HF Cybersecurity v1 | 1,889 |
| Atomic Red Team | 1,500 |
| CISA KEV | 1,396 |
| abuse.ch URLhaus | 1,133 |
| **Synthetic uncertainty (procedural)** | **780** |
| BleepingComputer | 109 |
| VirusTotal community | 44 |
| Mandiant Blog / SANS ISC | ~23 (collectors partly broken) |

Final dataset composition: 74.5% human-curated authoritative sources, 24.8% AI-generated (HF datasets), 0.7% procedural uncertainty examples.

Detailed source-by-source descriptions and licenses are in [`PROJECT_SUMMARY.md`](PROJECT_SUMMARY.md).

Exploratory analysis of the cleaned dataset (source distribution, length stats, IOC coverage, MITRE ATT&CK technique spread, kill chain phase coverage) is in [`eda.ipynb`](eda.ipynb), with charts also available as standalone PNGs in [`reports/eda/`](reports/eda/).

---

## Data Pipeline

The cleaning pipeline (`scripts/clean_pipeline.py`) converts raw collected text into instruction-tuning format:

1. HTML entity decoding, BBCode stripping, markdown link unwrapping
2. URL/IP defanging (`http` → `hxxp`, `.com` → `[.]com`)
3. Length filter (drop records under 30 chars)
4. CVE rejection filter (drop "REJECTED REASON:" records)
5. Exact deduplication (MD5)
6. Fuzzy deduplication (MinHash LSH @ 80% similarity)
7. Smart truncation at 4,096 chars (sentence boundary)
8. **Cross-split deduplication** to prevent train/valid/test leakage
9. Per-source instruction template generation (12 specialized templates)
10. Truncated-response detection and removal
11. Generic AI disclaimer filtering ("As an AI…", "I cannot…")

Output format:
```json
{
  "messages": [
    {"role": "system",    "content": "You are an expert cybersecurity analyst..."},
    {"role": "user",      "content": "Analyze this CVE..."},
    {"role": "assistant", "content": "Vulnerability: CVE-2021-44228..."}
  ],
  "source": "cve"
}
```

The pipeline does NOT need to be re-run to use the model — the v1 adapter is the artifact. The pipeline is included for reproducibility and to support future training rounds.

---

## Reproducibility

Training was done on **Kaggle free-tier T4 (single GPU, 16 GB)**. Library versions matter — the project was burned by version drift across `unsloth`, `transformers`, `trl`, and `bitsandbytes` during initial setup. Working pins for the production training notebook (`osint-ai.ipynb`):

```
transformers == 4.51.3
peft         == 0.14.0
trl          == 0.18.2
bitsandbytes >= 0.49.0
accelerate   >= 1.0
```

Key environment requirements (already learned the hard way; preserved here so the next person doesn't relearn them):

- **Force single-GPU before torch import.** Kaggle T4×2 + HF Trainer auto-wraps in `DataParallel`, which causes eval-time CUBLAS OOM. Set `os.environ["CUDA_VISIBLE_DEVICES"] = "0"` before `import torch`.
- **PEFT + 4-bit + grad-checkpointing.** Pass `gradient_checkpointing_kwargs={"use_reentrant": False}` or LoRA gradients silently break through the eval forward pass.
- **`trl 0.18.2` and batch size.** Per-device `batch_size > 1` triggers a `shift_labels` dimension mismatch in the accuracy metric. Keep `batch_size=1, grad_accum=16`.
- **`dataset_num_proc=1`.** Multi-process dataset prep can deadlock against bnb-4bit CUDA state.
- **Eval set sizing.** With `load_best_model_at_end=True`, HF Trainer runs eval *before* save in the same block — a crashing eval means no checkpoint. Subsample eval (used 500 of 5,720 validation records) and verify eval runs end-to-end in a sanity run before launching long training.

---

## Repository Layout

```
.
├── osint-ai.ipynb         # Production training notebook (Kaggle)
├── ai-test.ipynb          # Inference + smoke test notebook (used to ship v1)
├── eda.ipynb              # Exploratory data analysis (pre-executed)
├── scripts/
│   ├── clean_pipeline.py  # Cleaning + instruction template pipeline
│   ├── collect_*.py       # Per-source collectors (22 sources)
│   ├── eda.py             # Standalone EDA script (mirrors eda.ipynb)
│   ├── data_profiling.py  # Dataset profiling helpers
│   └── check_format.py    # Schema validation for cleaned records
├── reports/
│   └── eda/               # EDA chart outputs (PNGs)
├── PROGRESS_UPDATE.txt    # Full project history (decisions, bugs, trade-offs)
├── PROJECT_SUMMARY.md     # Detailed dataset and source documentation
└── README.md              # This file
```

Data, checkpoints, and logs are gitignored (data lives in `data/`, the LoRA checkpoint lives on HuggingFace at `Maximuz23/Text-OSINT`).

---

## Setting Up the Collectors

The collectors that pull from HuggingFace datasets read the HF token from the environment:

```bash
export HF_KEY=hf_xxxxxxxxxxxxxxxxxxxx
python scripts/collect_new.py
```

Other collectors need their own keys via environment variables — see each script for specifics.

---

## Roadmap

This v1 is the offline model layer. The complete OSINT assistant requires a live data layer on top, which is the next 2–3 weeks of work.

**Phase 7 — Live data layer.** A router that decides which APIs to query based on input type, fetches results, and feeds them into the fine-tuned model as context. Planned integrations:

- *Threat intel:* AlienVault OTX, NVD, VirusTotal, AbuseIPDB, Hybrid Analysis, abuse.ch
- *Target recon:* Shodan, Censys, IPinfo, crt.sh, WHOIS, GitHub
- *No-key sources:* crt.sh, WHOIS

**Phase 8 — Streamlit demo UI.** User pastes a threat artifact (IP, CVE, IOC, threat report), router queries relevant APIs, the model receives the artifact plus live API context and returns a structured red-team-focused OSINT brief.

---

## Acknowledgements

This model would not exist without the data providers listed in [`PROJECT_SUMMARY.md`](PROJECT_SUMMARY.md) — particularly the public-domain U.S. Government datasets (NVD, CISA KEV), the open threat intelligence community (abuse.ch, AlienVault OTX, MITRE ATT&CK), and the HuggingFace dataset community.

Built as part of the AI Builder Program (8-week cohort), Weeks 1–8.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Intended Use

This model is designed for **authorized** red team engagements, threat intelligence analysis, penetration testing support, and security research. It is not intended for unauthorized targeting or malicious use. All training data is sourced from public threat intelligence feeds and openly licensed datasets.
