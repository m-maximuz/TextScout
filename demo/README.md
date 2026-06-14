---
title: TextScout
emoji: 🛰️
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 8501
pinned: false
license: bigscience-openrail-m
---

# TextScout — red-team threat-intel chatbot

Ask in plain language. TextScout **retrieves** the matching real record (MITRE ATT&CK
groups / techniques / software, CISA KEV + NVD CVEs) and analyzes it with a fine-tuned
Llama-3.2-3B (LoRA adapter `Maximuz23/Text-OSINT`). When no record is found — an unknown
actor or a non-existent CVE — it **refuses to fabricate** (evidence-gated honesty).

**Repo & full write-up:** [github.com/m-maximuz/TextScout](https://github.com/m-maximuz/TextScout) · model [`Maximuz23/Text-OSINT`](https://huggingface.co/Maximuz23/Text-OSINT)

**Eval** (base Llama 3.2 3B → fine-tuned, 700-report test + 80-item probe): Honesty F1 0.62 → **0.99** · NER F1 0.60 → **0.88** · Hallucination 0.24 → **0.09**.

**Try it** (use the suggestion chips, or type your own):
- `CVE-2021-44228` — a real CVE → grounded assessment
- a fresh ThreatFox IP / domain / hash → live IOC enrichment (ThreatFox + OTX + VirusTotal)
- `APT-Lyrebird-77` or `CVE-9999-0001` → honest refusal (the differentiator)

## How it works (RAG)
1. Your message is routed to an entity: actor / CVE / technique / malware / report.
2. The matching record is retrieved from the bundled corpus (`corpus.json`, built from
   real MITRE ATT&CK + CISA KEV/NVD data). **Any CVE not in the snapshot is fetched LIVE
   from NVD + CISA KEV** — so fresh CVEs that were never in train/valid/test work too.
3. The record is formatted into the exact template the model was trained on; TextScout
   analyzes it. Empty lookup (unknown actor, non-existent CVE) → honest refusal.

## Files
`Dockerfile` · `app.py` · `requirements.txt` · `corpus.json` (retrieval data) · `robot.png`.

## Optional Space secrets
- `NVD_API_KEY` — higher NVD rate limit (CVE lookups work without it).
- `ABUSE_API_KEY` (abuse.ch unified Auth-Key → ThreatFox), `OTX_API_KEY`, `VT_API_KEY` —
  enable **live IOC enrichment**: a pasted IP / domain / hash / URL is looked up across
  abuse.ch ThreatFox, AlienVault OTX, and VirusTotal, formatted into a `[Threat Report]`,
  and analyzed. Without them the app still runs (the IOC text passes straight to the model).
  CISA KEV needs no key (it's a public JSON feed, fetched directly).

## Push updates
With the `hf` CLI authenticated, from the `osint-project` root:
```bash
hf upload Maximuz23/TextScout demo . --type space --commit-message update
```
The adapter `Maximuz23/Text-OSINT` is public, so no Space secret is needed.

## CPU vs GPU
Free CPU runs the 3B model in bf16 (~6 GB) — the first generation is ~30–60s (model load),
then faster; lower *Max new tokens* for snappier replies. For instant responses use a
**T4 small** (~$0.40/hr): switch the `Dockerfile` base to a CUDA image and uncomment
`bitsandbytes` in `requirements.txt`. Pause the Space after the demo.

## Contract — do not drift
`app.py`'s `SYSTEM_PROMPT` and record templates mirror `ai-test.ipynb` c03 and
`scripts/build_grounded_records.py`. If you retrain and the contract changes, update both
or the model goes off-distribution.

## Phase 2 (optional)
Swap the bundled `corpus.json` for **live** retrieval (NVD / CISA KEV / MITRE APIs) so the
demo reflects current ground truth instead of a snapshot. Needs NVD/OTX keys as secrets.
