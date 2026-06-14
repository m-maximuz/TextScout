import os
import re
import json
import base64
import random
import pathlib
import urllib.request
import urllib.parse

import streamlit as st
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

# --- model contract (mirror ai-test.ipynb cells 1 & 3) --------------------------
HF_REPO = "Maximuz23/Text-OSINT"
USE_GPU = torch.cuda.is_available()
BASE_MODEL = "unsloth/Llama-3.2-3B-Instruct-bnb-4bit" if USE_GPU else "unsloth/Llama-3.2-3B-Instruct"
MAX_NEW_TOKENS_DEFAULT = 384
HF_TOKEN = os.environ.get("HF_TOKEN")
ROBOT = str(pathlib.Path(__file__).parent / "robot.png")
CORPUS_PATH = pathlib.Path(__file__).parent / "corpus.json"

SYSTEM_PROMPT = (
    "You are an expert cybersecurity analyst specializing in Text OSINT and threat "
    "intelligence for red team operations. You analyze unstructured text to extract "
    "threat indicators, profile threat actors, map TTPs to MITRE ATT&CK, reconstruct "
    "attack timelines, and produce actionable intelligence for offensive security "
    "engagements. Work only from the record provided: extract and analyze what is present, "
    "and when a lookup is empty or no record is given, say so plainly instead of inventing "
    "details. Judge by the evidence in the input, not by whether a name looks familiar."
)

REFUSAL_HINTS = re.compile(
    r"no record (?:for|of|found)|won'?t fabricat|returns? no data|not indexed|no authoritative "
    r"record|cannot produce an assessment|no matching group|i cannot profile",
    re.I,
)


@st.cache_resource(show_spinner="Loading TextScout (Llama-3.2-3B + adapter)… first load is slow.")
def load_model():
    tok = AutoTokenizer.from_pretrained(BASE_MODEL, token=HF_TOKEN)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "left"
    kwargs = dict(token=HF_TOKEN)
    if USE_GPU:
        kwargs.update(device_map={"": 0}, torch_dtype=torch.float16)
    else:
        kwargs.update(torch_dtype=torch.bfloat16, low_cpu_mem_usage=True)
    base = AutoModelForCausalLM.from_pretrained(BASE_MODEL, **kwargs)
    base.config.use_cache = True
    model = PeftModel.from_pretrained(base, HF_REPO, token=HF_TOKEN)
    model.eval()
    return tok, model


def generate(user_prompt, max_new_tokens=MAX_NEW_TOKENS_DEFAULT):
    tok, model = load_model()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    inputs = tok.apply_chat_template(
        messages, tokenize=True, add_generation_prompt=True,
        return_tensors="pt", return_dict=True,
    )
    dev = next(model.parameters()).device
    inputs = {k: v.to(dev) for k, v in inputs.items()}
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=max_new_tokens,
                             do_sample=False, pad_token_id=tok.eos_token_id)
    return tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()


# --- record templates (mirror scripts/build_grounded_records.py) -----------------
def t_actor(a):
    aliases = ", ".join(a["aliases"]) if a.get("aliases") else "none recorded"
    techs = a.get("top_techniques") or []
    tb = "; ".join(f"{t['id']} {t['name']}" for t in techs) if techs else "none recorded"
    return ("Use only the MITRE ATT&CK record below to produce a red-team threat profile. "
            "Do not add any actor, technique, or attribution not present in the record.\n\n"
            "[MITRE ATT&CK Group lookup]\n"
            f"Name: {a['name']} ({a['attack_id']})\n"
            f"Aliases: {aliases}\n"
            f"Attributed techniques: {tb}\n"
            f"Description: {a['description']}")


def t_actor_empty(name):
    return ("Use only the MITRE ATT&CK record below to produce a red-team threat profile. "
            "Do not add any actor, technique, or attribution not present in the record.\n\n"
            "[MITRE ATT&CK Group lookup]\n"
            f"Query: {name}\n"
            "Result: no matching group found.")


def t_cve(c):
    desc = c.get("nvd_description") or c.get("kev_description") or ""
    cwes = ", ".join(c.get("cwes") or []) or "see description"
    vp = f"{c.get('vendor') or ''} {c.get('product') or ''}".strip()
    return ("Assess this CVE for offensive relevance using only the record below. "
            "Do not add details not present.\n\n"
            "[CVE Record]\n"
            f"CVE: {c['cve_id']}\n"
            f"Name: {c.get('name') or ''}\n"
            f"Vendor/Product: {vp}\n"
            f"Description: {desc}\n"
            f"CVSS: {c.get('cvss') or ''}\n"
            f"CWE: {cwes}\n"
            f"KEV ransomware use: {c.get('ransomware_use') or ''}\n"
            f"Required action: {c.get('required_action') or ''}")


def t_cve_empty(cid):
    return ("Assess this CVE for offensive relevance using only the record below.\n\n"
            "[CVE Record]\n"
            f"CVE: {cid}\n"
            "NVD lookup: no record found.\n"
            "CISA KEV: not listed.")


def t_tech(t):
    return ("Explain this MITRE ATT&CK technique and its offensive relevance. "
            "Use only the record provided.\n\n"
            "[MITRE ATT&CK Technique]\n"
            f"ID: {t['attack_id']}\n"
            f"Name: {t['name']}\n"
            f"Tactics: {', '.join(t.get('tactics') or []) or 'not specified'}\n"
            f"Platforms: {', '.join(t.get('platforms') or []) or 'not specified'}\n"
            f"Description: {t['description']}")


def t_soft(s):
    g = s.get("used_by_groups") or []
    return ("Explain this malware/tool and identify which threat actors use it. "
            "Use only the record provided.\n\n"
            "[MITRE ATT&CK Software]\n"
            f"ID: {s['attack_id']}\n"
            f"Name: {s['name']}\n"
            f"Type: {s.get('type') or ''}\n"
            f"Platforms: {', '.join(s.get('platforms') or []) or 'not specified'}\n"
            f"Description: {s['description']}\n"
            f"Documented user groups: {', '.join(g) if g else 'none recorded'}")


# --- live retrieval: NVD + CISA KEV (fresh CVEs not in the bundle) ---------------
def _get_json(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "TextScout-demo", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _env(*names):
    """First non-empty env var among `names`, so secret naming can vary."""
    for n in names:
        if os.environ.get(n):
            return os.environ[n]
    return None


@st.cache_data(ttl=3600, show_spinner=False)
def _kev_catalog():
    try:
        data = _get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
    except Exception:
        return {}                       # KEV is supplementary; degrade gracefully


@st.cache_data(ttl=3600, show_spinner=False)
def _nvd_lookup(cid):
    # raises on network error (so we can show "try again" rather than a false refusal);
    # returns None only when NVD answers with zero records.
    nvd_key = _env("NVD_API_KEY")
    headers = {"apiKey": nvd_key} if nvd_key else None
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + urllib.parse.quote(cid)
    vulns = _get_json(url, headers).get("vulnerabilities") or []
    return vulns[0]["cve"] if vulns else None


def live_cve(cid):
    """Build a CVE record from live NVD + KEV, or None if genuinely not found."""
    nvd = _nvd_lookup(cid)
    kev = _kev_catalog().get(cid)
    if not nvd and not kev:
        return None
    desc, cvss, cwes = "", "", []
    if nvd:
        desc = next((x["value"] for x in nvd.get("descriptions", []) if x["lang"] == "en"), "")
        metrics = nvd.get("metrics", {})
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                cd = metrics[k][0]["cvssData"]
                cvss = f"{cd.get('baseScore', '')} {cd.get('baseSeverity', '')} {cd.get('vectorString', '')}".strip()
                break
        cwes = list(dict.fromkeys(
            x["value"] for w in nvd.get("weaknesses", []) for x in w.get("description", [])
            if x.get("value", "").startswith("CWE")))
    return {
        "cve_id": cid,
        "name": (kev.get("vulnerabilityName") if kev else "") or "",
        "vendor": kev.get("vendorProject", "") if kev else "",
        "product": kev.get("product", "") if kev else "",
        "nvd_description": desc,
        "kev_description": kev.get("shortDescription", "") if kev else "",
        "cvss": cvss,
        "cwes": cwes,
        "ransomware_use": kev.get("knownRansomwareCampaignUse", "") if kev else "",
        "required_action": kev.get("requiredAction", "") if kev else "",
    }


# --- live IOC enrichment: ThreatFox + OTX + VirusTotal (uses Space secrets) ------
def _refang(s):
    return s.replace("[.]", ".").replace("[:]", ":").replace("hxxps", "https").replace("hxxp", "http")


def detect_ioc(q):
    q = _refang(q)                       # normalise defanged IOCs (hxxp, [.]) first
    m = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", q)
    if m:
        return m.group(0), "ip"
    m = re.search(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b", q)
    if m:
        return m.group(0), "file"
    m = re.search(r"https?://([^\s/:]+)", q, re.I)
    if m:
        host = m.group(1)
        return host, ("ip" if re.match(r"\d+\.\d+\.\d+\.\d+", host) else "domain")
    return None, None


# abuse.ch uses ONE unified Auth-Key across ThreatFox/URLhaus/MalwareBazaar; accept aliases.
ABUSE_KEYS = ("ABUSE_API_KEY", "THREATFOX_API_KEY")
OTX_KEYS = ("OTX_API_KEY", "ALIENVAULT_API_KEY", "OTX_KEY")
VT_KEYS = ("VT_API_KEY", "VIRUSTOTAL_API_KEY")


def _have_ioc_keys():
    return bool(_env(*ABUSE_KEYS, *OTX_KEYS, *VT_KEYS))


def _safe(fn, *a):
    try:
        return fn(*a)
    except Exception:
        return None


@st.cache_data(ttl=900, show_spinner=False)
def _threatfox(ioc):
    key = _env(*ABUSE_KEYS)
    if not key:
        return None
    body = json.dumps({"query": "search_ioc", "search_term": ioc}).encode()
    req = urllib.request.Request("https://threatfox-api.abuse.ch/api/v1/", data=body,
        headers={"Auth-Key": key, "Content-Type": "application/json", "User-Agent": "TextScout-demo"})
    d = json.loads(urllib.request.urlopen(req, timeout=15).read())
    rows = d.get("data") if d.get("query_status") == "ok" else None
    if not isinstance(rows, list) or not rows:
        return None
    return {
        "families": sorted({r.get("malware_printable") or r.get("malware") for r in rows if r.get("malware")}),
        "threat_types": sorted({r.get("threat_type_desc") or r.get("threat_type") for r in rows if r.get("threat_type")}),
        "confidence": max((r.get("confidence_level") or 0) for r in rows),
    }


@st.cache_data(ttl=900, show_spinner=False)
def _otx(ioc, ioc_type):
    key = _env(*OTX_KEYS)
    section = {"ip": "IPv4", "domain": "domain", "url": "url", "file": "file"}.get(ioc_type)
    if not key or not section:
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{urllib.parse.quote(ioc, safe='')}/general"
    req = urllib.request.Request(url, headers={"X-OTX-API-KEY": key, "User-Agent": "TextScout-demo"})
    pi = json.loads(urllib.request.urlopen(req, timeout=15).read()).get("pulse_info") or {}
    pulses = pi.get("pulses") or []

    def ids(p):
        return [a if isinstance(a, str) else a.get("id", "") for a in (p.get("attack_ids") or [])]
    fams = {m if isinstance(m, str) else m.get("display_name", "")
            for p in pulses for m in (p.get("malware_families") or [])} - {""}
    return {
        "pulse_count": pi.get("count", 0),
        "families": sorted(fams),
        "attack": sorted({a for p in pulses for a in ids(p) if a}),
        "adversary": next((p.get("adversary") for p in pulses if p.get("adversary")), ""),
        "industries": sorted({i for p in pulses for i in (p.get("industries") or [])}),
        "countries": sorted({c for p in pulses for c in (p.get("targeted_countries") or [])}),
    }


@st.cache_data(ttl=900, show_spinner=False)
def _vt(ioc, ioc_type):
    key = _env(*VT_KEYS)
    if not key:
        return None
    if ioc_type == "ip":
        path = "ip_addresses/" + ioc
    elif ioc_type == "domain":
        path = "domains/" + ioc
    elif ioc_type == "file":
        path = "files/" + ioc
    elif ioc_type == "url":
        path = "urls/" + base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
    else:
        return None
    req = urllib.request.Request("https://www.virustotal.com/api/v3/" + path,
        headers={"x-apikey": key, "User-Agent": "TextScout-demo"})
    a = (json.loads(urllib.request.urlopen(req, timeout=15).read()).get("data") or {}).get("attributes") or {}
    s = a.get("last_analysis_stats") or {}
    return {"malicious": s.get("malicious", 0), "total": sum(s.values()) if s else 0}


def enrich_ioc(ioc, ioc_type):
    tf = _safe(_threatfox, ioc)
    otx = _safe(_otx, ioc, ioc_type) or {}
    vt = _safe(_vt, ioc, ioc_type)
    families = sorted(set((tf or {}).get("families", []) + otx.get("families", [])))
    bits = []
    if tf:
        d = f"abuse.ch ThreatFox: {', '.join(tf['families']) or 'tracked indicator'}"
        if tf.get("threat_types"):
            d += f" ({', '.join(tf['threat_types'])})"
        if tf.get("confidence"):
            d += f", confidence {tf['confidence']}%"
        bits.append(d + ".")
    if vt and vt.get("total"):
        bits.append(f"VirusTotal: {vt['malicious']}/{vt['total']} engines flagged it malicious.")
    if otx.get("pulse_count"):
        bits.append(f"AlienVault OTX: referenced in {otx['pulse_count']} threat pulse(s).")
    if not bits:
        bits.append("No current threat-intelligence records for this indicator across ThreatFox, OTX, or VirusTotal.")
    label = {"ip": "IP Addresses", "domain": "Domains", "url": "URLs", "file": "File Hashes"}.get(ioc_type, "Indicators")
    # Only live feed data goes in the report — no canned recommendation (the model writes the analysis).
    return ("Analyze this threat intelligence report. Produce a structured red-team summary using only "
            "what the report states. Do not invent actors, malware, indicators, or recommendations; "
            "omit any line the record does not support.\n\n"
            "[Threat Report]\n"
            f"Title: Live IOC enrichment — {ioc}\n\n"
            f"{' '.join(bits)}\n\n"
            f"Reported indicators:\n  {label}: {ioc}\n"
            f"Analyst-tagged ATT&CK: {', '.join(otx.get('attack', [])) or 'none tagged'}\n"
            f"Malware families: {', '.join(families) or 'none named'}\n"
            f"Attributed actor: {otx.get('adversary') or 'none specified'}\n"
            f"Targeted industries: {', '.join(otx.get('industries', [])) or 'not specified'}\n"
            f"Targeted countries: {', '.join(otx.get('countries', [])) or 'not specified'}")


def ioc_summary(ioc, ioc_type):
    """One-line live-intel summary from the feeds — DISPLAY ONLY, not fed to the model."""
    tf = _safe(_threatfox, ioc)
    otx = _safe(_otx, ioc, ioc_type)
    vt = _safe(_vt, ioc, ioc_type)
    parts = []
    fams = sorted(set((tf or {}).get("families", []) + (otx or {}).get("families", [])))
    if fams:
        parts.append("🦠 " + ", ".join(fams[:3]))
    if tf and tf.get("threat_types"):
        tt = tf["threat_types"][0].lower()
        parts.append("C&C server" if any(k in tt for k in ("c&c", "command", "botnet"))
                     else "payload host" if any(k in tt for k in ("payload", "distribution"))
                     else tf["threat_types"][0])
    if tf and tf.get("confidence"):
        parts.append(f"ThreatFox {tf['confidence']}%")
    if vt and vt.get("total"):
        parts.append(f"VT {vt['malicious']}/{vt['total']}")
    if otx and otx.get("pulse_count"):
        parts.append(f"OTX {otx['pulse_count']} pulses")
    return " · ".join(parts) if parts else None


def recent_threatfox_ioc():
    """A random *current* abuse.ch ThreatFox IP indicator, so the demo chip hits live data."""
    key = _env(*ABUSE_KEYS)
    if not key:
        return None
    body = json.dumps({"query": "get_iocs", "days": 1}).encode()
    req = urllib.request.Request("https://threatfox-api.abuse.ch/api/v1/", data=body,
        headers={"Auth-Key": key, "Content-Type": "application/json", "User-Agent": "TextScout-demo"})
    d = json.loads(urllib.request.urlopen(req, timeout=15).read())
    rows = d.get("data") if d.get("query_status") == "ok" else None
    if not isinstance(rows, list) or not rows:
        return None
    pool = [r for r in rows if r.get("ioc_type") == "ip:port"] or rows
    return random.choice(pool).get("ioc", "").split(":")[0]


# --- bundled retrieval -----------------------------------------------------------
IOC_RE = re.compile(r"hxxp|https?://|\b\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}\b|\b[a-f0-9]{32,64}\b", re.I)
ACTOR_KW = re.compile(r"\b(actor|group|apt|adversary|profile|who is|what did|techniques does|ttps|campaign)\b", re.I)
REPORT_KW = re.compile(r"\b(extract|report|ioc|indicator|infrastructure|c2|c&c|phish)\b", re.I)


def _name_regex(names):
    uniq = sorted({n for n in names if len(n) >= 3}, key=len, reverse=True)
    return re.compile(r"(?<!\w)(" + "|".join(re.escape(n) for n in uniq) + r")(?!\w)", re.I)


@st.cache_resource(show_spinner=False)
def load_corpus():
    c = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    actor_idx, soft_idx = {}, {}
    for a in c["actors"]:
        for key in [a["name"], *a.get("aliases", [])]:
            if key:
                actor_idx.setdefault(key.lower(), a)
    for s in c["software"]:
        if len(s["name"]) >= 5:
            soft_idx.setdefault(s["name"].lower(), s)
    cve_idx = {x["cve_id"].upper(): x for x in c["cves"]}
    tech_idx = {x["attack_id"].upper(): x for x in c["techniques"]}
    return actor_idx, cve_idx, tech_idx, soft_idx, _name_regex(list(actor_idx)), _name_regex(list(soft_idx))


def _longest(rx, q):
    best = None
    for m in rx.finditer(q):
        if best is None or len(m.group(1)) > len(best):
            best = m.group(1)
    return best


def _guess_name(q):
    m = re.search(r"APT[\s\-]?[\w-]+", q, re.I)
    if m:
        return m.group(0)
    m = re.search(r"(?:actor|group|profile|about)\s+([A-Z][\w\- ]{2,40})", q)
    if m:
        return m.group(1).strip(" ?.")
    caps = re.findall(r"\b[A-Z][\w-]+\b", q)
    return " ".join(caps[:3]) if caps else q.strip()[:40]


HELP = (
    "I'm **TextScout** — I answer from retrieved threat-intel records. Try: "
    "**profile an actor** (APT28), **assess a CVE** (any id — fresh ones go to live NVD), "
    "**explain a technique** (T1059.001), **identify malware** (Cobalt Strike), or "
    "**extract IOCs from a report**. Pick a suggestion to see it."
)


def _hit(prompt, source):
    """A successful retrieval: the same text is both fed to the model and shown in the RAG expander."""
    return prompt, prompt, source, None


def route(q):
    """Map a user query to (user_prompt, retrieved_record_or_None, source_label, note_or_None)."""
    actor_idx, cve_idx, tech_idx, soft_idx, actor_re, soft_re = load_corpus()

    # CVE id -> bundled record, else live NVD + CISA KEV
    m = re.search(r"CVE-\d{4}-\d{4,}", q, re.I)
    if m:
        cid = m.group(0).upper()
        if cid in cve_idx:
            rec = cve_idx[cid]
            return _hit(rec.get("_prompt") or t_cve(rec), "bundled MITRE/KEV record")
        try:
            rec = live_cve(cid)
        except Exception:
            return None, None, None, "⚠️ Live NVD/CISA KEV lookup failed — please try again in a moment."
        if rec:
            return _hit(t_cve(rec), "live NVD + CISA KEV")
        return _hit(t_cve_empty(cid), "live NVD + CISA KEV (no record)")

    # ATT&CK technique id
    m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", q)
    if m and m.group(0).upper() in tech_idx:
        return _hit(t_tech(tech_idx[m.group(0).upper()]), "MITRE ATT&CK")

    # IOC -> live enrichment; if no keys, pass the raw report straight to the model
    if IOC_RE.search(q):
        ioc, ioc_type = detect_ioc(q)
        if ioc and _have_ioc_keys():
            prompt = _safe(enrich_ioc, ioc, ioc_type)
            if prompt:
                return _hit(prompt, "live ThreatFox + OTX + VirusTotal")
        return q, None, "the report you provided", None

    # actor or software name — longest match wins (so "Cobalt Strike" beats "Cobalt")
    a = _longest(actor_re, q)
    s = _longest(soft_re, q)
    if a or s:
        if len(s or "") > len(a or ""):
            return _hit(t_soft(soft_idx[s.lower()]), "MITRE ATT&CK Software")
        rec = actor_idx[a.lower()]
        return _hit(rec.get("_prompt") or t_actor(rec), "MITRE ATT&CK")

    # actor-intent but no match -> honest empty lookup; else a report keyword; else help
    if ACTOR_KW.search(q):
        return _hit(t_actor_empty(_guess_name(q)), "MITRE ATT&CK (no record)")
    if REPORT_KW.search(q):
        return q, None, "the report you provided", None
    return None, None, None, HELP


# --- UI --------------------------------------------------------------------------
st.set_page_config(page_title="TextScout", page_icon=ROBOT, layout="centered")
st.markdown("<h1 style='text-align:center; margin:0.2rem 0 1.4rem'>TextScout</h1>",
            unsafe_allow_html=True)

with st.sidebar:
    st.image(ROBOT, width=64)
    st.markdown("## TextScout")
    st.divider()
    max_tokens = st.slider("Max new tokens", 128, 512, MAX_NEW_TOKENS_DEFAULT, 32,
                           help="Lower for snappier CPU responses.")
    if st.button("🗑️ Clear chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

SUGGESTIONS = {
    "🎯 Profile the actor APT28": "Profile the threat actor APT28",
    "🧬 What does Kimsuky do?": "What techniques does the threat actor Kimsuky use?",
    "🛠️ Who uses Cobalt Strike?": "Which threat actors use the Cobalt Strike tool?",
    "📖 Explain technique T1059.001": "Explain MITRE ATT&CK technique T1059.001",
    "🔓 Assess CVE-2025-0282 (live)": "Assess CVE-2025-0282 for offensive relevance",
    "🌐 Look up a fresh live IOC": None,
}

if "messages" not in st.session_state:
    st.session_state.messages = []

clicked = None
if not st.session_state.messages:
    st.markdown("##### Try one of these 👇  ·  or type your own actor / CVE / IP / hash below")
    cols = st.columns(2)
    for i, (label, text) in enumerate(SUGGESTIONS.items()):
        if cols[i % 2].button(label, use_container_width=True):
            if text is None:                       # live IOC chip: grab a current indicator
                ioc = _safe(recent_threatfox_ioc)
                clicked = (f"Look up live threat intelligence for the indicator {ioc} "
                           "and assess its red team relevance." if ioc else
                           "Look up live threat intelligence for the indicator 1.1.1.1.")
            else:
                clicked = text

for msg in st.session_state.messages:
    with st.chat_message(msg["role"], avatar=ROBOT if msg["role"] == "assistant" else None):
        if msg.get("summary"):
            st.info(msg["summary"])          # live-intel card, straight from the feeds
        if msg.get("retrieved"):
            with st.expander(f"🔎 RAG — record retrieved from {msg.get('source', 'source')}"):
                st.code(msg["retrieved"])
        if msg.get("badge"):
            st.caption(msg["badge"])
        st.markdown(msg["content"])

user_input = st.chat_input("Ask TextScout… profile APT28 · assess CVE-2025-0282 · look up an IP/domain/hash") or clicked

if user_input:
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("assistant", avatar=ROBOT):
        with st.spinner("🔎 Retrieving + analyzing…"):
            prompt, retrieved, source, note = route(user_input)
            summary = None
            if note:
                answer, badge = note, None
            else:
                if source and source.startswith("live ThreatFox"):
                    dioc, dtype = detect_ioc(user_input)
                    summary = _safe(ioc_summary, dioc, dtype) if dioc else None
                answer = generate(prompt, max_new_tokens=max_tokens)
                badge = ("🛡️ No record retrieved → refused (honesty guardrail)"
                         if REFUSAL_HINTS.search(answer) else "✅ Grounded in the retrieved record")
    st.session_state.messages.append({"role": "assistant", "content": answer, "retrieved": retrieved,
                                      "source": source, "badge": badge, "summary": summary})
    st.rerun()
