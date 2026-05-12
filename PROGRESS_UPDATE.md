  OSINT-AI PROJECT — COMPLETE PROGRESS UPDATE
  Project: Text OSINT AI for Red Team Operations (AI Builder Program)
  Status as of: 2026-05-10 (Week 5 of 8)


## PART 1 — WHAT THE PROJECT IS

Goal: Build an AI assistant that helps red team analysts perform Text OSINT
(Open Source Intelligence) on cybersecurity threat data. The model takes
unstructured text (CVEs, log lines, threat reports, IOCs, malware names,
threat actor descriptions) and returns structured intelligence:

- IOC extraction (IPs, domains, hashes, CVEs)
- MITRE ATT&CK technique mapping
- Threat actor profiling and attribution
- Vulnerability assessment from offensive perspective
- Attack timeline reconstruction
- Kill chain phase identification

Why: Manual OSINT analysis takes 30-60 minutes per threat report, is
inconsistent across analysts, and requires deep expertise. A specialized
model can do this in seconds.

Approach: Fine-tune Llama 3.1 8B (or 3B) on 100K+ real cybersecurity
records using QLoRA (4-bit quantization + LoRA adapters) on free Kaggle
T4 GPU.


## PART 2 — WHAT WAS DONE BEFORE TODAY (Weeks 1-4)


### Data Collection
Built collection pipeline pulling from 22 different sources via APIs:

Authoritative threat intel:
- NVD/MITRE CVE         118,951 records  (vulnerability descriptions)
- Exploit-DB             33,976 records  (public exploits)
- GitHub Security        5,800  records  (GHSA advisories)
- CISA KEV               1,587  records  (actively exploited CVEs)
- MITRE ATT&CK           2,298  records  (techniques, malware, groups)
- Atomic Red Team        1,753  records  (red team test procedures)
- MISP Galaxy            3,860  records  (threat actor + malware profiles)
- abuse.ch URLhaus       1,134  records  (malicious URLs)
- ThreatFox              4,487  records  (malware IOCs)
- AlienVault OTX         8,420  records  (threat pulses)
- VirusTotal             74     records
- Mandiant Blog          20     records  (collector partly broken)
- SANS ISC               4      records  (collector partly broken)

Community / discussion:
- Telegram channels      3,539  records  (live threat intel)
- HackerNews security    5,000  records
- BleepingComputer       110    records  (security news)
- Wikipedia security     2,862  records  (security articles)

Academic / research:
- arXiv cs.CR            5,009  records  (academic security papers)

HuggingFace datasets (mix of human + AI generated):
- HF Fenrir v2.0         99,870 records  (down-sampled to 20K)
- HF Cybersecurity v1    2,410  records
- HF CTI                 7,603  records
- HF Loghub              3,461  records  (real SSH/Linux/Apache logs)

  TOTAL RAW: 312,228 records across 22 sources


### Data Cleaning
Built clean_pipeline.py to convert raw text into instruction-tuning format:

  1. HTML entity decoding (&amp; → &, etc.)
  2. BBCode tag removal ([b], [url])
  3. Markdown link unwrapping
  4. Defanging URLs/IPs (http→hxxp, .com→[.]com)
  5. Length filter (drop records under 30 chars)
  6. CVE rejection filter ("REJECTED REASON:")
  7. Exact deduplication (MD5)
  8. Fuzzy deduplication (MinHash LSH at 80% similarity)
  9. Smart truncation at 4096 chars (sentence boundary)
  10. Per-source instruction template generation:
      - CVE → vulnerability assessment + recon pivot
      - MITRE → TTP mapping + red team application
      - Logs → attack pattern reconstruction + kill chain
      - OTX → threat actor profiling + IOC extraction
      - Atomic Red Team → technique execution context
      - (12 specialized templates total)

  Output format per record:

```json
{"messages": [
    {"role": "system",    "content": "You are an expert cybersecurity..."},
    {"role": "user",      "content": "Analyze this CVE..."},
    {"role": "assistant", "content": "Vulnerability: CVE-2021-44228..."}
 ],
 "source": "cve"}
```


### Dataset Split
Split 90/5/5 into train/valid/test using random shuffle (seed=42).

EDA (Exploratory Data Analysis)
- Source distribution charts (~5 charts)
- Length distribution analysis
- Vocabulary analysis (security terms dominant)
- Temporal coverage (1988-2026)
- IOC coverage analysis (~45K records contain IOCs)


## PART 3 — WHAT WAS DONE TODAY (May 9-10, 2026)


### 3.1 Phase 2 Data Collection (recovered 5,677 New Records)
Problem: Phase 2 collection script was cut off the previous night before
finishing arXiv and MISP extra clusters.

Investigation: Atomic Red Team had completed (1,331 records) but arXiv
hadn't started — script was stuck retrying 404s on technique sub-IDs.

Fix:
- Patched collect_phase2_fix.py to skip retries on 404s
- Re-ran in background while building rest of project
Result:
- Atomic Red Team: +422 records (now 1,753 total)
- arXiv cs.CR: +5,009 records (NEW)
- MISP Extra: +246 records (now 3,860 total)
- Total raw: 312,228 records


### 3.2 Pipeline Re-run and Dataset Finalization
Re-ran clean_pipeline.py with full dataset:
- Final cleaned: 114,977 records
- Train/Valid/Test: 103,479 / 5,748 / 5,750


### 3.3 Data Quality Audit — Found and Fixed Multiple Issues
A. Cross-split data leakage detected:
- 28 records had identical user prompts in train AND valid
- 21 records had identical prompts in train AND test
- Cause: hf_fenrir source has paraphrased Q&A pairs
- Even though answers differed, this was treated as cheating risk
   FIX: Deduped across splits → 0 cross-split overlap

B. Truncated assistant responses:
- Found 1,200 records with mid-word/mid-sentence truncations
- Wrote smarter detection (checks for partial last words, not just

```
missing punctuation) so it didn't false-flag GHSA structured outputs
```

   FIX: Removed all 1,200 truncated records

C. Generic AI disclaimers:
- 194 records contained "I cannot...", "As an AI...", etc.
- These would teach bad behavior to the model
   FIX: Removed all 194

D. Smoke test prompt leakage:
- One of the original test prompts paraphrased an actual OTX record
- Model could regurgitate trained knowledge instead of reasoning
   FIX: Replaced with completely fresh aerospace/SpaceX scenario

  Final cleaned dataset: 113,533 → split → train 102,962 / valid 5,720 / test 5,729
  Cross-split overlap: 0
  Truncated records: 0
  Generic disclaimers: 0


### 3.4 Added Honesty/uncertainty Training Data (820 Records)
Concern: Without explicit teaching, the model would fabricate answers
(invent fake CVE numbers, made-up threat actor profiles, hallucinated
IOCs). For a red team tool this is dangerous.

Built synthetic uncertainty examples covering 8 categories:
- Fictional CVE numbers (CVE-9999-XXXXX) — 150 examples
- Fake threat actor names (APT-Phantom-91, etc.) — 150 examples
- Insufficient/empty input — 100 examples
- Live data requests ("what's happening NOW") — 100 examples
- Out-of-domain questions — 80 examples
- Future/prediction requests — 60 examples
- Random hash lookups — 100 examples
- Ambiguous queries — 80 examples

Critical detail: Each response was procedurally generated with random
combinations of phrases (not 3 fixed templates) so the model learns
the BEHAVIOR ("admit uncertainty") rather than memorizing specific text.

System prompt updated to include:
  "When you do not have reliable information about something, when input
   is insufficient, or when an identifier appears fictional or
   unrecognized, you say so explicitly rather than fabricating details.
   Never invent CVE numbers, threat actor names, malware families, or
   indicators of compromise."

Final dataset: 114,403 records:
- 85,214 (74.5%) human-curated content
- 28,321 (24.8%) AI-generated (HF datasets)
- 780 (0.7%) procedural uncertainty examples
- 0 cross-split leakage
- 0 truncations
- 0 generic disclaimers


### 3.5 Kaggle Fine-tuning Notebook — Iterative Debugging
Built fine-tuning notebook for Kaggle (free T4 x2 GPU).

Initial bugs caught during audit (BEFORE first run):
  1. HF_TOKEN undefined on Kaggle Secrets failure → added explicit None init
  2. save_steps=500 vs eval_steps=200 mismatch — would crash with

```
load_best_model_at_end=True (transformers requires multiple) — fixed both = 200
```

  3. Pip --upgrade after Unsloth — broke API compat — removed
  4. No early stopping → added EarlyStoppingCallback(patience=3, threshold=0.001)
  5. Markdown cells missing newlines → fixed JSON

Memory probe approach:
  Wrote a temporary cell that runs ONE forward+backward pass and reports
  GPU memory used. Used this to find the right LORA_R / sequence length
  combination before committing to long training runs.

The big debugging marathon (multiple Save Version → Run All cycles):

ATTEMPT 1: First run on Kaggle
  Error: HF_TOKEN AssertionError
  Cause: Kaggle Secrets not attached per-notebook (each notebook needs

```
explicit secret access toggle)
```

  Fix: User attached HF_TOKEN secret to notebook

ATTEMPT 2: Llama 3.1 license error
  Error: 401 Unauthorized for meta-llama/Meta-Llama-3.1-8B-Instruct
  Cause: HuggingFace renamed repos. User accepted license at old URL

```
(Meta-Llama-...) but actual model files redirect to new URL
(Llama-...) without user having access
```

  Fix: Switched to Unsloth's pre-quantized public republish:

```
unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit (no license gate)
```

ATTEMPT 3: Internet failure breaking Kaggle Secrets
  Error: ConnectionError fetching HF_TOKEN
  Cause: Kaggle Internet toggle was off (Kaggle Secrets is a network

```
service — needs internet to retrieve)
```

  Fix: User enabled Internet (required phone verification on Kaggle)

ATTEMPT 4: Dataset path error
  Error: FileNotFoundError /kaggle/input/osint-ai-dataset/train.jsonl
  Cause: Kaggle mounts dataset at /kaggle/input/datasets/<user>/<name>/,

```
not the expected path
```

  Fix: Updated DATASET_DIR to actual mount path

ATTEMPT 5: 'int' has no attribute 'mean'
  Error: AttributeError in Unsloth's _unsloth_training_step
  Cause: Kaggle's transformers 5.5.0 changed API. Unsloth's fused CE

```
loss expected a tensor with .mean() but transformers now passes
num_items_in_batch as int
```

  Fix: Pinned versions transformers==4.51.3, trl==0.18.2 (verified

```
compatible with Unsloth's pyproject.toml requirements)
```

ATTEMPT 6: Verified version pin worked
  Versions printed correctly:

```
unsloth: 2026.5.2
transformers: 4.51.3
trl: 0.18.2
```

ATTEMPT 7: ValueError dim mismatch in fused CE loss
  Error: input batch_size (1024) doesn't match target batch_size (1110)
  Cause: Unsloth's fused CE loss has a labels-handling bug with

```
transformers 4.51.3 (logits truncated to max_seq_length but
labels weren't)
```

  Failed fix: Setting UNSLOTH_RETURN_LOGITS=1 env var didn't bypass it

ATTEMPT 8: Tried older Unsloth (verified by inspecting wheel files)
- Downloaded multiple Unsloth-zoo wheels
- Confirmed fused_losses/cross_entropy_loss.py was added in 2025.8.4
- Last good version: 2025.8.3
- Pinned unsloth==2025.8.3, unsloth_zoo==2025.8.3

ATTEMPT 9: Old Unsloth had its OWN labels-shape assertion bug
  Error: AssertionError in fast_cross_entropy_loss
  Cause: Old Unsloth's fast_cross_entropy_loss expects labels.shape ==

```
(batch, seq_len), but newer transformers passes them differently
```

  Decision: After 8+ hours fighting Unsloth, decided to drop Unsloth

```
entirely and use plain transformers + PEFT
```

ATTEMPT 10: Plain transformers + PEFT setup
  Rewrote notebook to use:
- AutoModelForCausalLM (instead of FastLanguageModel)
- LoraConfig + get_peft_model + prepare_model_for_kbit_training
- Standard SFTTrainer (no Unsloth wrapping)
  Pinned: transformers 4.51.3, peft 0.14.0, trl 0.18.2, accelerate>=1.0
  Removed: bitsandbytes pin (Kaggle's 0.49.2 default has the

```
fixed triton.ops import; older pinned versions had a bug)
```

ATTEMPT 11: triton.ops bug in old bitsandbytes
  Error: ModuleNotFoundError: No module named 'triton.ops'
  Cause: bitsandbytes 0.45.0 (initial pin) imports from removed

```
triton.ops module. Triton 3.6 (Kaggle default) restructured.
```

  Verified by inspecting wheel files:
- 0.45.0 has bad import
- 0.49.0+ uses local .matmul_perf_model (works)
  Fix: Changed pin to bitsandbytes>=0.49.0

ATTEMPT 12: bitsandbytes not installed at all
  Error: PackageNotFoundError: No package metadata for bitsandbytes
  Cause: Earlier --force-reinstall removed bitsandbytes entirely
  Fix: Explicitly added bitsandbytes>=0.49.0 to install list

ATTEMPT 13: Wrong Llama license access
  Error: 401 Unauthorized for meta-llama/Llama-3.1-8B-Instruct
  Cause: User had accepted license for OLD URL (Meta-Llama-...) but

```
model files redirect to NEW URL
```

  Fix: Reverted to using Unsloth's public pre-quantized repo

ATTEMPT 14: API changed in trl 0.18.2 SFTTrainer
  Error: TypeError on SFTTrainer init
  Cause: Verified by inspecting wheel: trl 0.18.2 SFTTrainer signature

```
changed:
- tokenizer= → processing_class=
- dataset_text_field, max_seq_length, packing, dataset_num_proc
  moved from SFTTrainer to SFTConfig
- max_seq_length renamed to max_length
- SFTConfig replaces TrainingArguments
```

  Fix: Rewrote Cell 5 with new API (used SFTConfig + processing_class)

ATTEMPT 15: Multi-GPU device mismatch
  Error: Expected all tensors to be on same device (cuda:0 vs cuda:1)
  Cause: Kaggle has T4 x 2 (two GPUs). device_map="auto" split the

```
model across both, but loss computation expected single GPU
```

  Fix: Changed device_map="auto" → device_map={"": 0} (force GPU 0)

ATTEMPT 16: OOM on backward pass
  Error: CUDA out of memory at 13.96 GB / 14.56 GB
  Cause: Plain transformers needs ~2x memory of Unsloth (no fused

```
kernels, no smart activation offloading)
```

  Fix attempts (gradual):
- PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True (anti-frag)
- MAX_SEQ_LENGTH 512→256 (saved ~3 GB)
- LORA_R 32→16 (saved ~150 MB)
  Still hit OOM. Llama 3.1 8B + plain transformers + T4 doesn't fit
  comfortably for serious LoRA capacity.

DECISION: Switched to Llama 3.2 3B
  Verified by inspecting Unsloth's HF repo:
- File size: 2.10 GB (vs 5.31 GB for 8B)
- Architecture: same LlamaForCausalLM, same chat template
- Same target modules for LoRA
  Memory math: ~6 GB used / 14.56 GB → ~9 GB headroom
  Allowed bumping back to:
- LORA_R = 64 (max smart)
- MAX_SEQ_LENGTH = 2048 (full context)

ATTEMPT 17: Accuracy compute bug in trl 0.18.2 with batch>1
  Error: predictions(2) vs shift_labels(4) dim mismatch
  Cause: trl 0.18.2 SFTTrainer's accuracy metric computation has a

```
shape bug when per_device_train_batch_size > 1
```

  Fix: BATCH_SIZE=1, GRAD_ACCUM=16 (effective batch still 16)

ATTEMPT 18 (CURRENT): Training in progress
  Status: Model loaded, dataset loaded, training started
  Trainable params: 97,255,424 (5.12% of 1.9B)
  Approximately 20 minutes since training started, waiting for first
  loss log at step 25 (= 400 forward+backward passes at batch=1,
  grad_accum=16, seq=2048)


## PART 4 — FINAL CONFIGURATION (WHAT'S TRAINING NOW)

Base model:    Llama 3.2 3B Instruct (4-bit quantized via Unsloth's repo)
Method:        QLoRA — frozen base + trainable LoRA adapters
Training data: 102,962 instruction-tuning records
Validation:    5,720 records
Test:          5,729 records (held-out, unseen during training)

LoRA configuration:
  rank (r):           64
  alpha:              64
  dropout:            0
  target modules:     q_proj, k_proj, v_proj, o_proj, gate_proj,

```
up_proj, down_proj (all 7 standard layers)
```

  trainable params:   97,255,424 (5.12% of 1.9B total)

Training hyperparameters:
  max_seq_length:     2048
  batch_size:         1
  grad_accumulation:  16 (effective batch = 16)
  epochs:             1
  max_steps:          5000
  learning_rate:      1e-4
  scheduler:          cosine with 5% warmup
  weight_decay:       0.01
  optimizer:          paged_adamw_8bit
  precision:          fp16 (T4 doesn't support bf16)
  packing:            False
  gradient_checkpointing: True

Anti-overfitting defenses:
- 1 epoch only (102K samples, plenty of data, low overfit risk)
- LoRA r=64 (limited capacity vs 1.9B base)
- weight_decay 0.01
- cosine LR schedule with warmup
- EarlyStoppingCallback (patience=3, threshold=0.001)
- load_best_model_at_end=True
- Cross-split deduplication (0 leakage)

Evaluation:
- Validation loss every 200 steps during training
- Final test set evaluation after training (5,729 unseen records)
- 5 manual smoke test prompts:

```
1. IOC Extraction (real CobaltStrike IOC)
2. Threat Actor Profile (fresh aerospace/SpaceX scenario — never
   seen in training, tests pure generalization)
3. CVE Red Team Assessment (Log4Shell)
4. Honesty Check 1 (fictional CVE-9999-987654 — should refuse to invent)
5. Honesty Check 2 (fictional APT-Phantom-91 — should refuse to invent)
```

Output:
- LoRA adapter saved to /kaggle/working/osint-ai-lora
- Pushed to HuggingFace at Maximuz23/Text-OSINT (private)


## PART 5 — KEY DECISIONS AND TRADE-OFFS

1. Llama 3.1 8B → Llama 3.2 3B
   Why:   Plain transformers + 8B doesn't fit on free T4 with serious

```
LoRA capacity (only fits with severe seq/r reduction)
```

   Trade: 3B is less capable on general tasks, but specialized

```
fine-tuning on 102K narrow OSINT records produces a model
well-suited to the specific use case
```

   Future: Can retrain 8B on Colab Pro A100 ($10/month) post-program

2. Dropped Unsloth → Plain transformers
   Why:   Unsloth has multiple bugs with current transformers 4.51.3

```
(fused CE loss dim mismatch in new versions, label shape
assertion in old versions)
```

   Trade: ~2x slower training, no Unsloth memory optimizations
   Mitigation: Smaller 3B model means we have headroom anyway

3. Kept ~25% AI-generated data (HF Fenrir, Cyber v1)
   Why:   These provide Q&A structure and breadth of cybersecurity

```
concepts. Removing them would drop dataset to 86K records
and weaken general security knowledge
```

   Mitigation: 75% human-curated authoritative sources (NVD, MITRE,

```
Exploit-DB, CISA, Mandiant, etc.) form the backbone
```

4. Added 820 synthetic uncertainty records
   Why:   Without explicit teaching, model would fabricate CVE numbers

```
and threat actor profiles. For a red team tool, fabrication
is dangerous (false intel sends hunts the wrong way)
```

   How:   Procedurally generated from random phrase combinations (not

```
fixed templates) so model learns the behavior, not the text
```

5. BATCH_SIZE=1 forced by trl 0.18.2 accuracy bug
   Trade: Slightly slower (more grad_accum micro-batches per step)
   Mitigation: Effective batch (16) unchanged via grad_accum=16


## PART 6 — REMAINING WORK (Weeks 6-8)

Week 6 (after training completes):
- Review training/test loss numbers
- Read 5 smoke test outputs (knowledge + honesty)
- Iterate if quality is poor (try LORA_R=128, EPOCHS=2, etc.)

Week 7 (build live OSINT system):
- Build live_osint.py with API connectors:
- Threat Intel: OTX, NVD, VirusTotal, AbuseIPDB, Hybrid Analysis
- Target Recon: Shodan, Censys, IPinfo, crt.sh, WHOIS, GitHub
- Telegram channel monitoring
- Build Streamlit demo UI:
- Text input box
- Routes to relevant API queries based on input type
- Feeds API results + user query to fine-tuned model
- Returns structured OSINT report
- .env file with all API keys (already have most)

Week 8 (demo + presentation):
- Polish UI
- Prepare demo scenarios using real artifacts
- Final presentation


## PART 7 — TIME SPENT

Pre-week 5:  4 weeks total program, ~1 week on this project
Today:       ~12+ hours of intense debugging

```
(mostly fighting Unsloth/transformers/trl version compatibility
 bugs, then OOM debugging)
```

Lessons:
- Free Kaggle T4 (16GB) is genuinely small for Llama 3.1 8B
- Library version compatibility is the #1 risk in ML projects
- Memory probe before committing to long training is essential
- Verify by inspecting actual files (wheels, source code) instead

```
of guessing at versions
```

- Drop optimizations and use plain libraries when they break


## PART 8 — DATA SUMMARY (FOR REPORT)

Final training dataset:    114,403 records (cleaned, deduped, formatted)
Sources:                   22 distinct (15+ originally + 7 added in phase 2)
Origin breakdown:          74.5% human / 24.8% AI / 0.7% procedural

Top sources by clean record count:
  hf_fenrir            18,895
  exploitdb            19,199
  cve                  18,326
  otx                  8,288
  hf_cti               7,537
  ghsa                 5,728 (GitHub Security Advisories)
  arxiv_security       5,008
  hf_hackernews        4,986
  threatfox            4,366
  misp_galaxy          3,761
  telegram             3,331
  hf_loghub            3,223
  hf_wikipedia_security 2,858
  mitre_attack         2,212
  atomic_red_team      1,500
  cisa_kev             1,396
  abusech              1,133
  hf_cyber_v1          1,889
  synthetic_uncertainty  780
  bleepingcomputer     109
  virustotal           44
  mandiant_blog        19  (collector partly broken)
  sans_isc             4   (collector partly broken)

Splits (final, 0 cross-split leakage):
  Train:  102,962
  Valid:  5,720
  Test:   5,729


## PART 9 — WHAT WAS DONE TODAY (May 11-12, 2026)

Status going into today: ATTEMPT 18 was running on Kaggle Save Version
overnight (started May 10). Today we resumed to check results.


### 9.1 The First Kaggle Run Crashed (~5 Hours In, at First Eval)
Symptoms in log:
  [201/5000 4:53:40 < 118:01:58, 0.01 it/s, Epoch 0.06/2]
  RuntimeError: CUDA error: CUBLAS_STATUS_EXECUTION_FAILED
  ... in peft/tuners/lora/bnb.py forward, called via
  torch/nn/parallel/data_parallel.py parallel_apply

Two facts surfaced at once:
  (a) The 118-hour ETA proved the original config (5000 steps, seq 2048,

```
r=64) was structurally impossible — Kaggle session caps at 12 hours.
Even without the crash, the run would have died from timeout.
```

  (b) The crash happened DURING first eval at step 200, not during

```
training. Stack trace showed nn.DataParallel was active — HF
Trainer auto-wraps in DataParallel when it sees >1 GPU, even with
device_map={"": 0}. That doubled memory pressure during eval (which
doesn't use grad-checkpointing) and CUBLAS died as a masked OOM.
```

Critical detail about save behavior:
  With load_best_model_at_end=True, HF Trainer runs EVAL before SAVE in
  the _maybe_log_save_evaluate block. So when eval crashed at step 200,
  no checkpoint was ever written — 5 hours of compute, zero artifact.


### 9.2 Config Rewrite — Killing Dataparallel + Eliminating Waste
Changes applied in osint-ai.ipynb / test run.ipynb:

  Cell 1 — env + hyperparameters:

```bash
+ os.environ["CUDA_VISIBLE_DEVICES"] = "0"  (BEFORE torch import)
  → hides GPU 1 entirely so HF Trainer doesn't wrap in DataParallel
- MAX_SEQ_LENGTH  2048 → 1024  (p99 of training data = ~1080 tok,
                                attention O(L^2) so ~4x faster)
- LORA_R          64   → 32    (standard sweet spot for 3B, halves
                                trainable params)
- LORA_ALPHA      64   → 32    (alpha == r keeps scaling = 1.0)
- MAX_STEPS       5000 → 1500  (with packing this still covers ~60K
                                examples; original was impossible)
```

  Cell 4 — dataset prep:

```
+ Subsample valid_dataset to 500, test_dataset to 1000 (seeded shuffle).
  Original full evals (5,720 records / 5,729 records) would have eaten
  ~30 minutes per eval — 25 evals × 30 min = impossible in 12h cap.
```

  Cell 5 — SFTConfig:
- eval_steps                  200 → 500
- packing                     False → True   (~2.5x throughput, packs

```
                                              short examples into 1024-tok)
+ gradient_checkpointing_kwargs = {"use_reentrant": False}
  (PEFT + 4-bit + grad-ckpt compat fix — reentrant=True silently
   breaks grad flow through LoRA on eval forward pass)
- dataset_num_proc            2 → 1  (added later — see 9.3)
- EarlyStoppingCallback patience 3 → 2 (only 3 evals total now)
```

  Cell 7 — smoke tests:

```
+ Swapped honesty test #5 from APT-Phantom-91 to APT-Lyrebird-77
  after grep found Phantom-91 in 3 training records (synthetic
  uncertainty source). Original test would have measured memorization
  not generalization. Verified Lyrebird-77 absent from all splits.
```


### 9.3 Second Run — Silent 10-hour "hang" That Wasn't a Hang
Re-uploaded with fixes. Save Version showed log up to ~173s then went
silent for hours. At ~10h elapsed (35,800s) user killed the run.

Diagnosis was wrong at first: thought packing was hanging on
multiprocessing.fork() with bnb-4bit CUDA state. Switched to
dataset_num_proc=1 defensively (still correct change for robustness).

BUT the killed run had actually produced /kaggle/working/osint-ai/checkpoint-500
with:
- adapter_model.safetensors (194 MB)  ← real trained weights
- trainer_state.json
- optimizer.pt, scheduler.pt, rng_state.pth, scaler.pt
- tokenizer files

So the run wasn't hung — it was training successfully but the log just
wasn't streaming to the Save Version page. (Likely Kaggle log buffer
issue. Wall-clock 10h ÷ 500 steps ≈ 72 sec/step, slower than estimated
but real training.)


### 9.4 Checkpoint-500 Training Trajectory (from Trainer_state.json)
  Step     Train loss     Token accuracy
  25       2.7739         50.7%   ← starting (near-random)
  100      1.1709         76.4%
  200      0.9956         78.6%
  300      0.9477         79.7%
  400      0.9301         80.1%
  500      0.9084         80.4%   ← checkpoint we kept

  Eval @ step 500:  eval_loss = 0.9102, token accuracy = 80.7%,

```
eval_runtime = 133.6 sec (subsample worked).
```

  Key observations:
- Loss dropped 2.77 → 0.91 (3x reduction). Real learning happened.
- Train loss 0.9084 ≈ eval loss 0.9102 → NO OVERFITTING (cross-split

```
  dedup paid off).
- Grad norms 0.24-0.45 (healthy, no explosion/vanish).
- Curve was flattening between steps 400 and 500 (only 2% drop),
  suggesting diminishing returns at this point.
```

Decision made: ship checkpoint-500 as v1 instead of resuming. Reasons:
- Curve flattening; another 1000 steps would be another ~10 hours of

```
risky silent run on Kaggle for marginal gain.
```

- Better to test what we have first, decide based on actual quality.


### 9.5 Smoke Test Notebook Built (ai-test.ipynb)
Built dedicated inference notebook that:
- Loads base Llama 3.2 3B + LoRA adapter from checkpoint-500
- Uses peft_model.disable_adapter() context manager for base-vs-

```
fine-tuned side-by-side comparison (no need to load two models)
```

- Runs 5 smoke prompts
- Pushes adapter to HuggingFace Maximuz23/Text-OSINT (private)

Uploaded checkpoint-500 to Kaggle as a Dataset to attach to notebook.
Initial path bug: /kaggle/input/datasets/maximuz23/osint-checkpoint-500/
didn't contain adapter_config.json — checkpoint was nested one level
deeper because user uploaded the FOLDER, not its CONTENTS. Fixed path to
add /checkpoint-500 suffix.


### 9.6 Smoke Test Results — Honest Assessment
First run (default sampling):

WINS:
  + Honesty Check 2 (APT-Lyrebird-77): Base model FABRICATED a Chinese

```
MSS Unit 61398 attribution with custom "Lyrebird" backdoor. Pure
invention. Fine-tuned REFUSED cleanly. This is the differentiator
the project was built for.
```

  + Honesty Check 1 (CVE-9999-987654): Both refused (base's RLHF already

```
refuses fake CVEs, so fine-tune adds little here).
```

  + IOC Extraction: Fine-tuned produced more structured red-team output

```
(kill chain framing, JA3 fingerprinting, OSINT pivot guidance).
```

REGRESSIONS:
- Threat Actor Profile (Q2): Fine-tuned said "No machine-parseable

```
IOCs extracted" when the input clearly contained airdrop-update[.]com,
ns1.cdn-update[.]net, port 443, 47-min beacon. Base model actually
did the extraction.
```

- CVE Log4Shell (Q3): Fine-tuned gave generic "Vulnerability Class:

```
Unclassified" output. Base gave a specific exploitation breakdown.
Synthetic uncertainty records made the model over-hedge on KNOWN CVEs.
```

- Q5 had a repetition loop: "I don't know if they are a threat actor."

```
× 50. Classic sampling pathology with temperature=0.1.
```

- Q1 hallucinated "cobaltstrike[.]com" domain that wasn't in input.


### 9.7 Sampling Fix
First attempt (too aggressive):
  repetition_penalty = 1.15
  no_repeat_ngram_size = 4
  → Killed the loop, but MANGLED defanged IOC notation:

```
"139[.]59[.]226[.]78" → "139[.]" (truncated)
"airdrop-update[.]com" → "airdrop/update[.]com"
".com" → ".cm"  (the n-gram penalty hit "[.]" repetition)
```

Second attempt (tuned):
  repetition_penalty = 1.05    (gentle)
  no_repeat_ngram_size = 10    (only catches long-phrase loops)
  → Loop still gone, IPs reproduce cleanly now.
  → Q2 still mangles some domain names ("airdrop-update" → "airdrop/update",

```
"ns1.cdn-update[.]net" → "cdn-update[.]org"). This is NOT a sampling
issue at this level — it's a 3B-model verbatim-extraction limitation
combined with training data that generated "IOC-shaped" rather than
"exact copy" outputs.
```

  → Q2 also FABRICATED a SHA hash that wasn't in input. The refusal

```
behavior didn't generalize from "fake actor names" to "fake hashes" —
coverage gap in training data.
```

  → Q3 still gives generic CVE response (didn't fix).


### 9.8 Huggingface Push Saga
First push attempt: 401 Unauthorized.
Diagnosis path:
  1. Suspected fine-grained token without repo permission. Reasonable

```
but wrong.
```

  2. Added whoami() probe + write test (.token-write-test scratch file)

```
to verify token from inside notebook. Found token was reported
"Invalid user token" by HF whoami endpoint — not just read-only,
genuinely unrecognized.
```

  3. Root cause: the token VALUE in Kaggle Secrets was stale. User had

```
regenerated the token on HF but the Kaggle Secret HF_TOKEN still
held the OLD string, which HF had revoked.
```

  4. Fix: User generated fresh Classic token with Write role, replaced

```
the Kaggle Secret value, re-tested with the probe cell.
```

  5. Verified working: User=Maximuz23, Role=write, Can write to

```
Maximuz23/Text-OSINT: YES.
```

After token fix:
- model.push_to_hub(HF_REPO, token=HF_TOKEN, private=True) → success
- Adapter live at https://huggingface.co/Maximuz23/Text-OSINT (private)


### 9.9 V1 Shipped — Documented Limitations
Adapter on HuggingFace: Maximuz23/Text-OSINT (private)
Source checkpoint:      step 500 of intended 1500
Training reached:       ~0.2 epochs (102K samples × 0.2 = ~20K seen)
Train loss:             0.9084
Eval loss:              0.9102 (no overfit)

KNOWN LIMITATIONS to be honest about in the week-5 update:
  1. Verbatim extraction is unreliable — model occasionally mutates

```
input domains/URLs ("airdrop-update" → "airdrop/update",
".com" → ".cm") rather than copying exactly.
```

  2. Hash fabrication observed — on Q2 the model invented a SHA-like

```
string that wasn't in the input. Coverage gap: synthetic
uncertainty training covered fake CVEs and fake actors but not
fake hashes.
```

  3. CVE analysis regressed vs base — synthetic uncertainty records made

```
the model over-hedge on real CVEs (says "Unclassified" / "verify
CVSS" instead of giving specific analysis).
```

  4. Only 500 / 1500 steps trained. Loss curve was flattening but more

```
training might have helped Q3 specifically.
```

KEY DIFFERENTIATOR (the win to lead with):
  Base Llama 3.2 3B fabricates threat actor profiles when asked about
  unknown identifiers. My fine-tune refuses without inventing details.
  Demo'd with APT-Lyrebird-77 (fictional, verified absent from training
  data). Base: invented Chinese MSS attribution with custom backdoor.
  Fine-tune: "I don't know this one. Maybe it's a typo?" — appropriate
  refusal.


## PART 10 — CURRENT STATE (END OF May 12)

Artifacts:
  Local:      ~/osint-project/checkoint-500/   (full checkpoint folder)
  Kaggle:     osint-checkpoint-500 dataset
  HuggingFace: Maximuz23/Text-OSINT (private)  ← v1 lives here

Notebooks in repo:
  osint-ai.ipynb        — training notebook (production config 1500/500)
  test run.ipynb        — training notebook (sanity config 50/25)
  ai-test.ipynb         — inference + smoke test notebook (USED for v1 eval)
  smoke_test.ipynb      — earlier draft of inference notebook (superseded)

Helper scripts:
  check_hf_token.py     — local terminal script to verify HF token works

```
(run: python3 ~/osint-project/check_hf_token.py)
```

Quota status (Kaggle T4):
  ~30h/week budget
  Spent: ~5h (crashed run) + ~10h (silent 500-step run that worked) +

```
~10 min × 2 (smoke test runs) = ~15h
```

  Remaining this week: ~15h

GPU bugs we now KNOW about and have fixes for (do not re-fall-into):
- Kaggle T4×2 + HF Trainer → wraps in DataParallel → eval CUBLAS OOM

```bash
FIX: os.environ["CUDA_VISIBLE_DEVICES"] = "0" before torch import
```

- load_best_model_at_end=True: eval runs BEFORE save in same block,

```
so a crashing eval = no checkpoint
FIX: smaller eval set + verified eval works in sanity run first
```

- PEFT + 4-bit + grad-ckpt + use_reentrant=True can break LoRA grad flow

```
FIX: gradient_checkpointing_kwargs = {"use_reentrant": False}
```

- dataset_num_proc=2 + bnb-4bit can deadlock via fork()+CUDA state

```
FIX: dataset_num_proc=1
```

- trl 0.18.2: batch_size > 1 → shift_labels dim mismatch

```
FIX: BATCH_SIZE=1, GRAD_ACCUM=16
```

- Smoke test prompts: verify identifiers ABSENT from training data

```
before using them as honesty tests, otherwise you measure memorization
FIX: grep against all splits before adding any new test identifier
```

Tomorrow's plan: Create a GitHub repo for this project (not started yet).

  END OF UPDATE
