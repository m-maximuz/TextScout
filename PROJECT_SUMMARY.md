# Text OSINT AI — Complete Project Summary

**Program:** AI Builder Program (8-week cohort)
**Status:** v1 shipped — LoRA adapter live at [Maximuz23/Text-OSINT](https://huggingface.co/Maximuz23/Text-OSINT) on HuggingFace
**GitHub:** [m-maximuz/TEXT-OSINT-AI](https://github.com/m-maximuz/TEXT-OSINT-AI)

---

## 1. Problem Statement

### The Problem
Red team operators perform **Open Source Intelligence (OSINT)** before and during engagements — reading threat reports, vulnerability descriptions, log files, forum posts, and dark web text to extract useful intelligence. This work is:
- **Time-consuming:** A single threat report takes 30–60 minutes to manually analyze
- **Inconsistent:** Different analysts extract different things from the same text
- **Expertise-dependent:** Understanding IOCs, TTPs, MITRE ATT&CK, and attribution requires years of experience

### The Solution
Fine-tune Llama 3.2 3B on cybersecurity threat intelligence data so it can:
- Extract indicators of compromise (IOCs) from any text
- Map described behaviors to MITRE ATT&CK techniques
- Profile threat actors from written descriptions
- Assess vulnerabilities from an offensive perspective
- Reconstruct attack timelines from log text
- **Refuse to invent intelligence about unrecognized identifiers** — the core differentiator

### Why Machine Learning?
Rule-based systems (regex, keyword matching) already exist for IOC extraction but fail at:
- Understanding context ("this IP belongs to a researcher, not an attacker")
- Reasoning about unstructured narrative text
- Identifying implied TTPs not explicitly stated
- Attributing behavior to known threat actors

A fine-tuned LLM learns patterns from thousands of real analyst-written intelligence reports and can reason across all of these simultaneously.

---

## 2. The Key Differentiator — Honest Refusal

The most important property of this model is one that the base model does NOT have: **it refuses to fabricate intelligence about unknown identifiers.**

**Test:** *"Profile threat actor APT-Lyrebird-77."* (fictional name, verified absent from all training splits)

| Model | Response |
|---|---|
| Base Llama 3.2 3B | Fabricated a Chinese MSS Unit 61398 attribution with a custom "Lyrebird" backdoor. Pure invention. |
| **This fine-tune** | "I don't have reliable information on this threat actor. The identifier may be a typo or unrecognized alias…" |

For a red team tool, fabrication is dangerous — false attribution sends investigations the wrong way. This property was trained explicitly via **780 procedurally-generated uncertainty examples** (see Section 4.4).

### Known Limitations (v1)
1. **Verbatim extraction is unreliable** — model occasionally mutates input domains/URLs (`airdrop-update` → `airdrop/update`, `.com` → `.cm`). Partly a 3B model-size limitation.
2. **Hash fabrication observed** — model invented a SHA-like string not present in input on one smoke prompt. Honesty training covered CVEs and actor names but not hashes — coverage gap.
3. **CVE analysis regressed vs base** — synthetic uncertainty records caused the model to over-hedge on real CVEs ("Unclassified" / "verify CVSS" instead of giving analysis). Data-mix issue.
4. **500 of 1500 planned steps trained** — loss was flattening; shipped to test quality before spending more GPU quota. The three limitations above are data-mix issues, not fixable by more steps.

---

## 3. Data Collection

### Why We Built a Custom Dataset
No single dataset exists for "text OSINT for red teams." We assembled 114,403 records from 22 distinct sources by:
1. Writing per-source collection scripts with different APIs, authentication methods, and data formats
2. Converting raw threat intelligence into instruction-tuning format (system / user / assistant)
3. Building custom cleaning, deduplication, and response-generation logic

### Phase 1 — Initial Collection

| Source | What It Is | Records |
|---|---|---|
| NVD/MITRE CVE | 118K vulnerability descriptions (downsampled) | 118,951 → 18,326 |
| Exploit-DB | 34K public exploit metadata | 33,976 → 19,199 |
| AlienVault OTX | Threat intelligence pulses | 8,420 → 8,288 |
| HF Fenrir v2.0 | Red team Q&A, AI-generated (downsampled) | 99,870 → 18,895 |
| HF CTI | Real threat intel articles | 7,603 → 7,537 |
| ThreatFox | Malware IOC indicators | 4,487 → 4,366 |
| Telegram channels | CVE alerts, live threat intel | 3,539 → 3,331 |
| HF HackerNews | Security community discussions (filtered) | 5,000 → 4,986 |
| Wikipedia Security | Security concept articles (filtered) | 2,862 → 2,858 |
| BleepingComputer | Security news (RSS) | 110 → 109 |
| VirusTotal | Malware analysis comments | 74 → 44 |

**3 sources rejected after inspection:**
- `hf_phishing_email` — was the Enron spam/ham corpus, not cybersecurity content
- `hf_phishing` — 45% bare URLs with no text content
- `security_news` — 91% exact duplicates of BleepingComputer

### Phase 2 — Additional Collection (reduce AI-generated %, add real data)

| Source | What It Is | Records |
|---|---|---|
| GHSA | GitHub package vulnerability advisories | 5,800 → 5,728 |
| arXiv cs.CR | Academic security research papers | 5,009 → 5,008 |
| MISP Galaxy | Threat actor + malware profiles (Malpedia) | 3,860 → 3,761 |
| Loghub | Real SSH/Linux/Apache logs (3 log types) | 3,461 → 3,223 |
| HF Cyber v1 | Security Q&A, AI-generated | 2,410 → 1,889 |
| Atomic Red Team | Human-written ATT&CK test procedures | 1,753 → 1,500 |
| CISA KEV | Confirmed actively-exploited vulnerabilities | 1,587 → 1,396 |
| abuse.ch URLhaus | Live malware download URLs | 1,134 → 1,133 |
| MITRE ATT&CK | Techniques, malware, threat groups (STIX) | 2,298 → 2,212 |
| Mandiant Blog | APT attribution reports (RSS) | 20 → 19 |
| SANS ISC | Daily security threat diaries | 4 → 4 |

### Raw Totals
- **Total raw records:** 312,228 across 22 sources
- **After full cleaning pipeline:** 114,403 records

---

## 4. Data Cleaning

### Problems Found and Fixed

| Problem | Solution |
|---|---|
| HTML entities (`&amp;`, `&#x27;`) | `html.unescape()` |
| BBCode tags (`[b]`, `[url]`) | Regex removal |
| Markdown links (`[text](url)`) | Unwrap to plain text |
| Live URLs/IPs that could be dangerous | Defang: `http://` → `hxxp://`, `.com` → `[.]com` |
| Records too short to be useful (<30 chars) | Filtered out |
| Rejected CVE records | Filter records starting with "REJECTED REASON:" |
| Exact duplicate records | MD5 hash deduplication |
| Near-duplicate records | MinHash LSH fuzzy dedup at 80% similarity |
| Truncated records (mid-word/mid-sentence) | Remove all 1,200 truncated records |
| Generic AI disclaimers ("As an AI…") | Remove all 194 disclaimer records |
| Cross-split leakage | Deduplicate prompts across train/valid/test splits |

### Cross-Split Deduplication
Found 28 records with identical user prompts in train AND valid, and 21 in train AND test (from paraphrased HF Fenrir Q&A pairs). Fixed to ensure **zero cross-split leakage** — test set truly unseen during training.

### Instruction-Tuning Format
Each raw record was converted into a training conversation:
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

12 specialized response templates, one per source type:
- CVE → vulnerability assessment + recon pivot advice
- MITRE ATT&CK → TTP mapping + red team application
- Logs → attack pattern reconstruction + kill chain phase
- OTX → threat actor profiling + IOC extraction
- Atomic Red Team → technique execution context + detection footprint
- arXiv → research findings + offensive implications
- etc.

### Honesty / Uncertainty Training Data
Without explicit teaching, the model fabricates answers for unknown identifiers. Added **780 procedurally-generated uncertainty examples** covering:

| Category | Examples |
|---|---|
| Fictional CVE numbers (CVE-9999-XXXXX) | 150 |
| Fake threat actor names | 150 |
| Insufficient / empty input | 100 |
| Live data requests ("what's happening NOW") | 100 |
| Random hash lookups (unknown hashes) | 100 |
| Out-of-domain questions | 80 |
| Ambiguous queries | 80 |
| Future / prediction requests | 60 |

Each response was procedurally generated from **random phrase combinations** (not fixed templates) so the model learns the *behavior* of admitting uncertainty, not specific refusal text.

### Final Dataset

| Split | Records |
|---|---|
| Train | 102,962 |
| Validation | 5,720 |
| Test | 5,729 |
| **Total** | **114,411** |

| Composition | Records | % |
|---|---|---|
| Human-curated / API-sourced | 93,571 | 81.8% |
| AI-generated (HF Fenrir + Cyber v1) | 20,832 | 18.2% |
| Cross-split leakage | 0 | 0% |
| Truncated records | 0 | 0% |
| Generic AI disclaimers | 0 | 0% |

---

## 5. Exploratory Data Analysis

Full EDA with inline charts: [`eda.ipynb`](eda.ipynb). Standalone chart PNGs: [`reports/eda/`](reports/eda/).

### Source Distribution
Top 3 sources (Exploit-DB 16.8%, HF Fenrir 16.6%, NVD CVE 16.0%) together account for ~50% of the corpus. The remaining 19 sources each contribute 0.0%–7.2%, providing breadth across threat intel, academic research, community discourse, and red team procedures.

### Real vs AI-Generated
81.8% human-curated authoritative sources, 18.2% AI-generated Q&A. The AI-generated subset provides structured Q&A format and breadth; the human-curated backbone ensures real-world accuracy.

### Text Length Distribution
- Median user-message length: **315 characters**
- p95: **1,628 characters**
- p99: **2,294 characters**

This drove the choice of `max_seq_length = 1024` — it captures the large majority of training records while keeping attention compute manageable (O(L²), so 1024 vs 2048 is ~4× faster).

### IOC Coverage
- **54,719 records (47.8%)** contain at least one defanged IOC pattern
- CVE IDs are the most common (40,016 records / 35.0%), followed by defanged domains (15,394 / 13.5%) and URLs (12,624 / 11.0%)
- Defanged IPs (4,416) and hashes (1,710) are less common — these are the coverage gaps that contributed to the hash fabrication limitation in v1

### MITRE ATT&CK Coverage
- **Top technique: T1078** (Valid Accounts) with 5,287 mentions
- Second: T1055 (Process Injection) with 4,416 mentions
- The dataset references ATT&CK techniques across all phases from Reconnaissance to Impact

### Kill Chain Phase Coverage
- **Reconnaissance: 70,129 records (61.3%)** — dominates because OSINT and discovery content is most common in public threat intel
- **Initial Access: 19,356 (16.9%)** — second largest (phishing, watering hole, etc.)
- All 10 phases covered; Impact phase (1,608 records) is the least represented

---

## 6. Model — Fine-Tuning Llama 3.2 3B

### Model Choice: Why Llama 3.2 3B
The original plan was Llama 3.1 8B. After extensive debugging (18 Kaggle run attempts), we switched to **Llama 3.2 3B** for these reasons:
- 8B + plain transformers + PEFT did not fit on a single T4 with meaningful LoRA capacity (required severe sequence length and rank reductions that defeated the purpose)
- 3.2 3B is ~2.1 GB vs ~5.3 GB for 8B — fits comfortably on a single T4 with proper training config
- Same architecture (LlamaForCausalLM), same target modules for LoRA, same chat template
- On a **specialized** 102K narrow OSINT dataset, a well-trained 3B is more useful than a poorly-trained 8B

Trade-off: 3B is less capable on general tasks. A retrain on 8B or a larger model is post-program work once hardware budget allows.

### Why QLoRA
Full fine-tuning 3B parameters still requires significant GPU memory and hours. QLoRA:
1. Loads the base model in **4-bit quantization** (8× memory reduction)
2. Freezes all original weights
3. Adds small trainable LoRA adapter matrices (~1.5% of parameters)
4. Trains only the adapters — fast, cheap, and reversible

### Training Configuration

| Setting | Value | Reason |
|---|---|---|
| Base model | `unsloth/Llama-3.2-3B-Instruct-bnb-4bit` | Pre-quantized, no license gate |
| LoRA rank (r) | 32 | Standard sweet spot for 3B |
| LoRA alpha | 32 | alpha = r keeps scaling = 1.0 |
| Trainable params | 48.6M (1.5% of 3.21B) | Sufficient adapter capacity |
| Max seq length | 1,024 | p99 of training data ≈ 1,080 tokens |
| Batch size | 1 (grad accum 16) | trl 0.18.2 accuracy bug with batch > 1 |
| Effective batch | 16 | Via gradient accumulation |
| Learning rate | 1e-4 | Standard for QLoRA |
| LR scheduler | Cosine with 5% warmup | Smooth decay |
| Weight decay | 0.01 | Anti-overfitting |
| Packing | True | Packs short examples into 1024-token sequences (~2.5× throughput) |
| Max steps | 1,500 (planned) | 500 actually trained — see results |
| Optimizer | paged_adamw_8bit | Memory-efficient AdamW |
| Hardware | Kaggle T4 (single GPU, 16 GB) | Free tier |

### Key Environment Fixes (Learned the Hard Way)
- **`CUDA_VISIBLE_DEVICES=0` before torch import** — Kaggle T4×2 auto-wraps in DataParallel, causing CUBLAS OOM at eval. Hiding GPU 1 entirely prevents this.
- **`gradient_checkpointing_kwargs={"use_reentrant": False}`** — PEFT + 4-bit + grad-checkpointing silently breaks LoRA grad flow with `use_reentrant=True`.
- **`dataset_num_proc=1`** — multi-process dataset prep deadlocks against bnb-4bit CUDA state.
- **`load_best_model_at_end=True`**: eval runs *before* save in the same block — a crashing eval = no checkpoint. Subsample eval set and test it with a sanity run before committing to 10+ hours.

### Training Results

| Metric | Value |
|---|---|
| Steps trained | 500 of 1,500 planned |
| Epochs completed | 0.20 (20,600 of 102,962 examples seen) |
| Train loss | 0.9084 |
| Eval loss | 0.9102 |
| Train token accuracy | 80.4% |
| Eval token accuracy | 80.7% |
| Overfitting | None (eval ≈ train) |

Loss dropped from 2.77 (random) to 0.91 — **3× reduction**. Gradient norms 0.24–0.45 (healthy). Loss was flattening between steps 400–500 (only 2% drop), suggesting diminishing returns. Shipped at step 500 to test quality before spending more Kaggle quota.

### Smoke Test Results (5 Prompts)

| Prompt | Base Model | Fine-Tune |
|---|---|---|
| IOC Extraction (CobaltStrike C2) | Basic extraction | Structured red-team output with kill chain framing |
| Threat Actor Profile (SpaceX scenario) | Partial extraction | Partial — some IOC mutation observed |
| CVE Red Team Assessment (Log4Shell) | Reasonable analysis | Over-hedges — says "Unclassified" (known regression) |
| Honesty Check: fictional CVE-9999-987654 | Refuses (RLHF already handles) | Refuses cleanly |
| Honesty Check: fictional APT-Lyrebird-77 | **Fabricates** Chinese MSS attribution + custom backdoor | **Refuses** cleanly — the key differentiator |

---

## 7. Deployment

### v1 Shipped Artifacts

| Artifact | Location |
|---|---|
| LoRA adapter | [Maximuz23/Text-OSINT](https://huggingface.co/Maximuz23/Text-OSINT) (HuggingFace, private) |
| Local backup | `~/osint-project/checkpoint-500/` |
| Training notebook | `osint-ai.ipynb` (runs on Kaggle T4) |
| Inference + smoke test | `ai-test.ipynb` (runs on Kaggle T4) |
| GitHub repo | [m-maximuz/TEXT-OSINT-AI](https://github.com/m-maximuz/TEXT-OSINT-AI) |

### Loading the Adapter

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

### Planned: Live OSINT Layer (Phase 7)
The v1 model operates on static input text. The production system adds a **live data router** that queries real APIs and feeds results as context before calling the model:

| Data type | Planned API integrations |
|---|---|
| Threat intel | AlienVault OTX, NVD, VirusTotal, AbuseIPDB, Hybrid Analysis, abuse.ch |
| Target recon | Shodan, Censys, IPinfo, crt.sh, WHOIS, GitHub |
| No-key sources | crt.sh, WHOIS |

Final demo: Streamlit UI — user pastes a threat artifact (IP, CVE, IOC, threat report text), the router queries relevant APIs, model receives artifact + live context, returns a structured red-team OSINT brief.

---

## 8. Data Sources

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
