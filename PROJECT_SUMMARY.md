# OSINT-AI: Text OSINT for Red Team Operations
## Complete Project Summary — What Was Done and Why

---

## 1. Problem Statement (Why We're Doing This)

### The Problem
Red team operators perform **Open Source Intelligence (OSINT)** before and during engagements — reading threat reports, vulnerability descriptions, log files, forum posts, and dark web text to extract useful intelligence. This is:
- **Time-consuming**: A single threat report takes 30–60 minutes to manually analyze
- **Inconsistent**: Different analysts extract different things from the same text
- **Requires expertise**: Understanding IOCs, TTPs, MITRE ATT&CK, attribution requires years of experience

### The Solution
Fine-tune a large language model (Llama 3.1 8B) specifically on cybersecurity threat intelligence data so it can:
- Extract indicators of compromise (IOCs) from any text
- Map described behaviors to MITRE ATT&CK techniques
- Profile threat actors from written descriptions
- Assess vulnerabilities from an offensive perspective
- Reconstruct attack timelines from log text
- Produce structured intelligence reports

### Why Machine Learning?
Rule-based systems (regex, keyword matching) already exist for IOC extraction, but they fail at:
- Understanding context ("the IP address belongs to a researcher, not an attacker")
- Reasoning about unstructured narrative text
- Identifying implied TTPs not explicitly stated
- Attributing behavior to known threat actors

A fine-tuned LLM solves all of these by learning patterns from thousands of real analyst-written intelligence reports.

---

## 2. Metrics and Baselines

### Baseline
The baseline is **Llama 3.1 8B Instruct (unmodified)** — the same model before fine-tuning. This tells us what the model can already do with just its general training, and how much fine-tuning improves it.

### Metrics We Measure

| Metric | What It Measures | How |
|---|---|---|
| **Validation Loss** | How well the model predicts the next token during training | Logged every 200 steps by the trainer |
| **ROUGE-L** | Overlap between model output and reference answer | Computed on test set after training |
| **IOC Extraction Accuracy** | Does the model correctly extract IPs, domains, hashes, CVEs? | Manual evaluation on 50 test samples |
| **TTP Identification** | Does the model correctly identify MITRE ATT&CK techniques? | Manual check against known ground truth |
| **Before vs. After Comparison** | How much did fine-tuning improve over base model? | Run same prompts on both models |

### Current Baseline (before fine-tuning)
Base Llama 3.1 8B gives generic cybersecurity answers but:
- Does not defang URLs/IPs
- Does not consistently output MITRE technique IDs
- Does not follow the structured response format
- Treats all CVEs with equal importance (doesn't know CISA KEV means actively exploited)

---

## 3. Data Collection — What Was Collected and How

### Why We Can't Use Ready-Made Datasets
No single dataset exists for "text OSINT for red teams." We had to build it from scratch by:
1. Collecting from 15+ different real-world sources via APIs
2. Converting raw threat intelligence into instruction-tuning format (question → answer pairs)
3. Custom deduplication, cleaning, and analytical response generation

This is the **non-trivial** part of the project.

### Sources Collected (in order of collection)

#### Phase 1 — Initial Collection
| Source | What It Is | How Collected | Records |
|---|---|---|---|
| abuse.ch URLhaus | Live malware download URLs | REST API (Auth-Key) | 1,134 |
| CISA KEV | Confirmed exploited vulnerabilities | Public JSON feed | 1,587 |
| NVD/MITRE CVE | 118K vulnerability descriptions | NVD REST API (API key) | 118,951 → 20,000 |
| AlienVault OTX | Threat intelligence pulses | OTX API (API key) | 8,420 |
| MITRE ATT&CK | Techniques, malware, threat groups | STIX bundles (GitHub) | 2,298 |
| ThreatFox | Malware IOC indicators | ThreatFox API (Auth-Key) | 4,487 |
| Loghub | Real SSH/Linux/Apache logs | Raw GitHub CDN | 3,461 |
| Telegram channels | CVE alerts, threat intel | Telegram API (client) | 3,539 |
| HF Fenrir v2.0 | Red team Q&A (AI-generated) | HuggingFace API | 99,870 → 20,000 |
| HF Cyber v1 | Security Q&A (AI-generated) | HuggingFace API | 2,410 |
| HF CTI | Real threat intel articles | HuggingFace API | 7,603 |
| HF HackerNews | Security community discussions | HuggingFace API (filtered) | 5,000 |
| Wikipedia Security | Security concept articles | HuggingFace API (filtered) | 2,862 |
| BleepingComputer | Security news | RSS feed | 110 |
| VirusTotal | Malware analysis comments | VT API (API key) | 74 |

**3 sources were removed after inspection:**
- `hf_phishing_email` — was actually the Enron spam/ham email corpus, not cybersecurity
- `hf_phishing` — 45% were bare URLs with no text content
- `security_news` — 91% were exact duplicates of BleepingComputer

#### Phase 2 — Additional Collection (to add real data, reduce AI-generated %)
| Source | What It Is | Records |
|---|---|---|
| MISP Galaxy | Threat actor + malware profiles (986 actors, Malpedia) | 3,614 |
| GHSA | GitHub package vulnerability advisories | 5,800 |
| Exploit-DB | 34K verified public exploit metadata | 33,976 |
| Atomic Red Team | Human-written ATT&CK test procedures (in progress) | ~700 |
| Mandiant Blog | APT attribution reports via RSS | 20 |
| SANS ISC | Daily security threat diaries | 4 |
| arXiv cs.CR | Academic security research papers | ~2,000 |

### Why This Is Non-Trivial
- All 15+ sources required separate collection scripts with different APIs, authentication, and data formats
- Raw data had to be standardized, deduplicated, and converted into a completely new format (instruction-tuning pairs)
- The collection pipeline generates analytical responses from raw text — this required building custom NLP logic (IOC extractor, vulnerability classifier, kill chain mapper, threat actor identifier)
- No single source gives you instruction-tuning data — we manufactured the training format

---

## 4. Data Cleaning — What Was Done and Why

### Problems Found in Raw Data

| Problem | Source | Solution |
|---|---|---|
| HTML entities (`&amp;`, `&#x27;`) | All web-scraped sources | `html.unescape()` |
| BBCode tags (`[b]`, `[url]`) | Forum/VT data | Regex removal |
| Markdown links (`[text](url)`) | MITRE, Telegram | Unwrap to plain text |
| Live URLs that could be dangerous | All sources | Defanging: `http://` → `hxxp://`, `.com` → `[.]com` |
| Escaped newlines (`\n` as literal text) | HF Fenrir | Replace `\\n` → actual newline |
| Records too short to be useful (<30 chars) | Phishing URLs, sparse records | Filtered out |
| Rejected CVE records | NVD CVE | Filtered records starting with "REJECTED REASON:" |
| Exact duplicate records | All sources | MD5 hash deduplication |
| Near-duplicate records | Log files, threat feeds | MinHash LSH fuzzy deduplication (80% similarity threshold) |
| Truncated at dangerous lengths | Long CTI reports | Smart truncate at 4096 chars, split on sentence boundary |

### Deduplication Strategy
Used **MinHash LSH** (Locality-Sensitive Hashing) — a probabilistic algorithm that efficiently finds near-duplicate text without comparing every pair:
- **Strict threshold (80% similarity)**: Used for CTI reports, CVEs, news — removes paraphrased duplicates
- **Loose threshold (95% similarity)**: Used for logs, IOC feeds — keeps slight variations (different IP, same pattern) because those are valid distinct records

### Instruction-Tuning Format Generation
Each raw record was converted into a training conversation:
```
System:  "You are an expert cybersecurity analyst specializing in Text OSINT..."
User:    "Analyze this CVE from a red team offensive perspective: [real CVE text]"
Assistant: "Vulnerability: CVE-2021-44228
            Vulnerability Class: Remote Code Execution (RCE)
            Attack Vector: Network/Remote — unauthenticated...
            Attacker Capability: Full remote compromise..."
```

Every source has its own response template tailored to what it teaches:
- CVE records → vulnerability assessment + recon pivot advice
- MITRE ATT&CK → TTP mapping + red team application
- Logs → attack pattern reconstruction + kill chain phase
- OTX reports → threat actor profiling + IOC extraction
- Atomic Red Team → technique execution context + detection footprint
- etc.

### Final Dataset Stats
| | Count |
|---|---|
| Raw records collected | ~305,000 |
| After removing bad sources | ~261,000 |
| After cleaning + dedup | **~80,000–130,000** |
| AI-generated (Fenrir + Cyber v1) | ~22,000 (17–27%) |
| Real human-written / API-sourced | ~58,000–108,000 (73–83%) |

---

## 5. Exploratory Data Analysis (EDA)

### What EDA Revealed
(Full code in `scripts/eda.py` and `notebooks/eda.ipynb`)

**Source distribution**: CVE and Fenrir dominate at ~23% each. All other sources are 1–10% each. This is intentional — CVE provides broad vulnerability knowledge, Fenrir provides Q&A structure.

**Text length distribution**:
- Short records (100–500 chars): ThreatFox, abusech, telegram
- Medium records (500–2000 chars): CVE, CISA KEV, MITRE
- Long records (2000–4096 chars): OTX reports, CTI articles, Wikipedia

**Vocabulary analysis**: High frequency of domain-specific terms: CVE, exploit, malware, ransomware, authentication, privilege, lateral movement, command-and-control — confirms the dataset is genuinely security-focused.

**Temporal coverage**: CVE data spans 1988–2026. OTX, ThreatFox, Telegram data is from 2025–2026 (recent threat landscape). This gives the model both historical context and current threat awareness.

**IOC coverage**: ~45,000 records contain at least one extractable IOC (IP, domain, hash, CVE ID).

---

## 6. Modeling — Fine-Tuning Llama 3.1 8B

### Why Llama 3.1 8B
- Best publicly available model in the 7–8B parameter range
- Free to fine-tune (Meta community license)
- 128K token context window — handles long threat reports
- Strong English instruction following
- Fits in Kaggle's free T4 GPU (16GB) with QLoRA

### Why QLoRA (not full fine-tuning)
Full fine-tuning 8B parameters requires 8× A100 GPUs and costs thousands of dollars.
QLoRA (Quantized Low-Rank Adaptation):
1. Compresses model weights from 32-bit to 4-bit (reduces VRAM 8×)
2. Freezes all original weights
3. Adds small trainable "adapter" layers (only ~0.2% of parameters)
4. Trains only the adapters — much faster, much cheaper

Result: Fine-tuning an 8B model on a single free T4 GPU in ~8–12 hours.

### Training Configuration
| Setting | Value | Reason |
|---|---|---|
| LoRA rank (r) | 16 | Good balance of capacity vs. VRAM |
| Learning rate | 2e-4 | Standard for QLoRA |
| Batch size | 2 + grad accum 4 | = effective batch 8, fits in 16GB |
| Epochs | 1 | 100K+ records means 1 epoch = enough exposure |
| Packing | True | Packs short samples into 2048-token sequences → 4× faster |
| Scheduler | Cosine | Smooth learning rate decay |

### Validation
- Validation loss logged every 200 steps on held-out valid set
- Best model checkpoint saved automatically
- Manual evaluation on 50 test samples after training

### Error Analysis
After training, we evaluate failures:
- Does the model hallucinate CVE IDs that don't exist?
- Does it miss IOCs that are present in the text?
- Does it confuse threat actors (e.g., attribute Russian TTPs to Chinese actors)?
- Does it produce responses that are too generic?

---

## 7. Responsive / Real-World Implementation

### How the Model Is Used
After training, the model can be:
1. **Run locally** via Ollama (GGUF format) — fast, private, no API costs
2. **Integrated into red team tooling** — call as an API during engagements
3. **Used in a Gradio web interface** — text in, analysis out

### Example Real-World Use Cases
- Paste a threat actor's forum post → get attribution indicators and TTP mapping
- Feed a system log file → get attack timeline reconstruction
- Input a CVE description → get red team exploitation assessment
- Submit a phishing email → get social engineering technique analysis

---

## 8. Data Sources Credit

| Source | URL | License |
|---|---|---|
| abuse.ch URLhaus | https://urlhaus.abuse.ch | CC0 |
| ThreatFox | https://threatfox.abuse.ch | CC0 |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Public Domain |
| NVD/MITRE CVE | https://nvd.nist.gov | Public Domain |
| AlienVault OTX | https://otx.alienvault.com | Community |
| MITRE ATT&CK | https://attack.mitre.org | Apache 2.0 |
| MISP Galaxy | https://github.com/MISP/misp-galaxy | Apache 2.0 |
| Loghub | https://github.com/logpai/loghub | MIT |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | MIT |
| GitHub GHSA | https://github.com/advisories | GitHub ToS |
| Exploit-DB | https://www.exploit-db.com | Offensive Security |
| Mandiant Blog | https://www.mandiant.com/resources/blog | Fair use (RSS) |
| SANS ISC | https://isc.sans.edu | Fair use (RSS) |
| HF Fenrir v2.0 | https://huggingface.co/datasets/AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0 | See dataset card |
| HF Cyber v1 | https://huggingface.co/datasets/AlicanKiraz0/Cybersecurity-Dataset-v1 | See dataset card |
| HF CTI | https://huggingface.co/datasets/mrmoor/cyber-threat-intelligence | See dataset card |
| HF HackerNews | https://huggingface.co/datasets/open-index/hacker-news | See dataset card |
| Wikipedia | https://huggingface.co/datasets/wikimedia/wikipedia | CC BY-SA 4.0 |
| arXiv cs.CR | https://arxiv.org | arXiv license |
