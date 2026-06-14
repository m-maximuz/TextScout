import json, os, re, html, logging, hashlib, random
from datasketch import MinHash, MinHashLSH

RAW     = os.path.expanduser("~/osint-project/data/01_raw")
OUT     = os.path.expanduser("~/osint-project/data/02_processed")
LOG_DIR = os.path.expanduser("~/osint-project/logs")
os.makedirs(OUT, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/cleaning_audit.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

DOWNSAMPLE = {
    'cve.jsonl':       20000,
    'hf_fenrir.jsonl': 20000,
}

DOMAIN_WHITELIST = {
    'mitre.org', 'attack.mitre.org', 'cve.mitre.org',
    'nvd.nist.gov', 'github.com', 'virustotal.com',
    'abuse.ch', 'urlhaus.abuse.ch', 'threatfox.abuse.ch'
}

# ============================================================
# Text Cleaning
# ============================================================

def defang_urls(text):
    text = re.sub(r'http://', 'hxxp://', text)
    text = re.sub(r'https://', 'hxxps://', text)
    text = re.sub(
        r'(?<=[a-zA-Z0-9])\.(com|net|org|io|ru|cn|cz|de|uk|fr|jp|kr|xyz|top|info|biz|bet|surf|site|gov|edu|mil)(?=[/\s\'\">\)\.]|$)',
        r'[.]\1', text
    )
    return text

def unescape_html(text):
    return html.unescape(text)

def remove_bbcode(text):
    for tag in ['b', 'i', 'u', 'url', 's', 'strike', 'quote', 'code', 'size', 'color']:
        text = re.sub(rf'\[{tag}(?:=[^\]]+)?\]', '', text, flags=re.IGNORECASE)
        text = re.sub(rf'\[/{tag}\]', '', text, flags=re.IGNORECASE)
    return text

def remove_markdown_links(text):
    text = re.sub(r'\[([^\]]+)\]\((https?://[^\)]+)\)', r'\1 (\2)', text)
    text = re.sub(r'\[([^\]]+)\]\(#[^\)]*\)', r'\1', text)
    text = re.sub(r'!\[[^\]]*\]\([^\)]+\)', '', text)
    return text

def remove_markdown_formatting(text, source=''):
    if source not in ('hf_loghub', 'virustotal_comments'):
        text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'\*{2,3}(.*?)\*{2,3}', r'\1', text)
    if source != 'hf_loghub':
        text = re.sub(r'(?<!\w)\*([^*\n]+)\*(?!\w)', r'\1', text)
    text = re.sub(r'~~(.*?)~~', r'\1', text)
    text = re.sub(r'(?<!\w)_([^_\n]+)_(?!\w)', r'\1', text)
    return text

def smart_truncate(text, max_len=4096):
    if len(text) <= max_len:
        return text
    cut = text[:max_len]
    for sep in ['\n', ' ', '.']:
        idx = cut.rfind(sep)
        if idx > max_len * 0.8:
            return cut[:idx].strip()
    return cut.strip()

def normalize_whitespace(text):
    text = text.replace('\\n', '\n').replace('\\t', ' ')  # unescape literal \n sequences
    text = re.sub(r'\r\n|\r', '\n', text)
    text = re.sub(r'\t', ' ', text)
    text = re.sub(r' {2,}', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()

def clean_text(text, source=''):
    text = unescape_html(text)
    if source in ('mitre_attack', 'telegram'):
        text = remove_markdown_links(text)
    text = remove_bbcode(text)
    text = remove_markdown_formatting(text, source=source)
    text = defang_urls(text)
    text = normalize_whitespace(text)
    text = smart_truncate(text, max_len=4096)
    return text

def filter_record(text, source='', min_len=30):
    if not text or len(text.strip()) < min_len:
        return False
    if source == 'cve' and text.lower().startswith('rejected reason:'):
        return False
    return True

# ============================================================
# MinHash Dedup
# ============================================================

def get_shingles(text, k=5):
    text = text.lower()
    return set(text[i:i+k] for i in range(len(text) - k + 1))

def make_minhash(text, num_perm=64):
    m = MinHash(num_perm=num_perm)
    for s in get_shingles(text):
        m.update(s.encode('utf8'))
    return m

# ============================================================
# Analysis Helpers
# ============================================================

def infer_vuln_type(text):
    t = text.lower()
    checks = [
        (['remote code execution', ' rce ', 'arbitrary code execution'], 'Remote Code Execution (RCE)'),
        (['sql injection', ' sqli '], 'SQL Injection'),
        (['cross-site scripting', ' xss '], 'Cross-Site Scripting (XSS)'),
        (['privilege escalation', 'elevation of privilege'], 'Privilege Escalation'),
        (['path traversal', 'directory traversal'], 'Path Traversal'),
        (['authentication bypass', 'auth bypass', 'missing authentication', 'improper authentication'], 'Authentication Bypass'),
        (['buffer overflow', 'stack overflow', 'heap overflow', 'out-of-bounds write'], 'Memory Corruption / Buffer Overflow'),
        (['command injection', 'os command injection'], 'Command Injection'),
        (['deserialization', 'insecure deserialization'], 'Insecure Deserialization'),
        (['ssrf', 'server-side request forgery'], 'Server-Side Request Forgery (SSRF)'),
        (['xxe', 'xml external entity'], 'XML External Entity (XXE)'),
        (['use after free', 'use-after-free'], 'Use-After-Free'),
        (['information disclosure', 'information exposure', 'sensitive data exposure'], 'Information Disclosure'),
        (['denial of service', 'resource exhaustion'], 'Denial of Service (DoS)'),
        (['csrf', 'cross-site request forgery'], 'Cross-Site Request Forgery (CSRF)'),
        (['file upload', 'unrestricted upload'], 'Unrestricted File Upload'),
        (['open redirect'], 'Open Redirect'),
        (['race condition', 'time-of-check'], 'Race Condition (TOCTOU)'),
        (['insecure direct object', ' idor '], 'Insecure Direct Object Reference (IDOR)'),
        (['session fixation', 'session hijack'], 'Session Hijacking'),
    ]
    for keywords, label in checks:
        if any(k in t for k in keywords):
            return label
    return 'Unclassified — review CVE details for CWE classification'

def infer_attack_vector(text):
    t = text.lower()
    if any(k in t for k in ['unauthenticated', 'remotely exploitable', 'over the network', 'internet-facing', 'no authentication required']):
        return 'Network/Remote — unauthenticated, exploitable over the internet (highest priority for attack surface mapping)'
    if any(k in t for k in ['authenticated user', 'requires login', 'valid credentials', 'logged-in']):
        return 'Network/Authenticated — requires valid credentials (relevant post-compromise or via credential stuffing)'
    if any(k in t for k in ['adjacent network', 'same network segment', 'local network']):
        return 'Adjacent Network — requires network proximity (relevant for lateral movement scenarios)'
    if any(k in t for k in ['local access', 'physical access', 'local attacker', 'local user']):
        return 'Local — requires local or physical access'
    return 'Network (inferred) — verify CVSS AV vector for confirmation'

def infer_kill_chain_phase(text):
    t = text.lower()
    phases = [
        (['reconnaissance', ' recon ', 'scanning', 'enumeration', 'footprinting', 'osint collection'], 'Reconnaissance'),
        (['weaponize', 'payload development', 'exploit development', ' poc '], 'Weaponization'),
        (['phishing', 'spear phishing', 'initial access', 'watering hole', 'drive-by', 'supply chain attack'], 'Initial Access'),
        (['code execution', 'shellcode', 'macro execution', 'script execution'], 'Execution'),
        (['persistence', 'backdoor', 'rootkit', 'scheduled task', 'autorun', 'registry run key'], 'Persistence'),
        (['privilege escalation', 'privesc', 'elevation of privilege', 'uac bypass', 'token impersonation'], 'Privilege Escalation'),
        (['credential dump', 'lsass', 'mimikatz', 'pass the hash', 'kerberoasting', 'credential harvesting'], 'Credential Access'),
        (['lateral movement', 'psexec', 'wmiexec', 'rdp pivot', 'smb relay', 'pass-the-ticket'], 'Lateral Movement'),
        (['c2', 'c&c', 'command and control', 'beacon', 'cobalt strike', 'sliver', 'havoc', 'brute ratel'], 'Command & Control'),
        (['exfiltration', 'data exfil', 'data theft', 'exfiltrate'], 'Exfiltration'),
        (['ransomware', 'encrypt files', 'wiper', 'destructive', 'impact'], 'Impact'),
    ]
    found = []
    for keywords, phase in phases:
        if any(k in t for k in keywords):
            found.append(phase)
    return ' → '.join(found[:3]) if found else 'Multi-phase / Unclassified'

def extract_threat_actor(text):
    named = [
        'Lazarus Group', 'Fancy Bear', 'Cozy Bear', 'APT28', 'APT29', 'APT41',
        'Volt Typhoon', 'Salt Typhoon', 'Silk Typhoon', 'Midnight Blizzard',
        'Scattered Spider', 'Lapsus$', 'UNC3944', 'TeamPCP',
        'LockBit', 'Conti', 'REvil', 'BlackCat', 'ALPHV', 'Cl0p', 'Akira',
        'Play', 'Black Basta', 'RansomHub', 'DarkSide', 'Hive', 'Royal',
        'Equation Group', 'Shadow Brokers', 'Mustang Panda', 'BlackTech',
    ]
    for actor in named:
        if actor.lower() in text.lower():
            return actor
    for pat in [r'\b(APT-?\d+)\b', r'\b(FIN\d+)\b', r'\b(UNC\d+)\b', r'\b(TA-?\d+)\b', r'\b(G\d{4})\b']:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None

def extract_malware_families(text):
    known = [
        'Cobalt Strike', 'CobaltStrike', 'Metasploit', 'Mimikatz', 'BloodHound',
        'SharpHound', 'Sliver', 'Havoc', 'Brute Ratel', 'BruteRatel',
        'Emotet', 'TrickBot', 'QakBot', 'Qbot', 'IcedID', 'BazarLoader',
        'Ryuk', 'REvil', 'LockBit', 'BlackCat', 'ALPHV', 'Conti', 'DarkSide',
        'BlackMatter', 'Hive', 'Play', 'Akira', 'Royal', 'Black Basta',
        'njRAT', 'AsyncRAT', 'Agent Tesla', 'Raccoon', 'RedLine', 'Vidar',
        'Dridex', 'SystemBC', 'PlugX', 'QuasarRAT', 'Remcos', 'NanoCore',
        'NetWire', 'BitRAT', 'DcRAT', 'XWorm', 'Warzone', 'Gh0st RAT',
    ]
    t = text.lower()
    return list({f for f in known if f.lower() in t})

def extract_mitre_techniques(text):
    return sorted(set(re.findall(r'T\d{4}(?:\.\d{3})?', text)))

def ioc_confidence(source):
    if source in ('threatfox', 'abusech', 'cisa_kev'):
        return 'High — curated threat intelligence feed with active verification'
    if source in ('otx', 'hf_cti', 'telegram'):
        return 'Medium — threat reporting source, verify before operational use'
    return 'Low/Unverified — extracted from unstructured text, requires corroboration'

# ============================================================
# IOC Extractor
# ============================================================

def extract_iocs(text, source=''):
    ips = set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text))
    hashes = set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text))
    domains = set(re.findall(
        r'\b(?:[a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\[\.\][a-zA-Z]{2,10}\b', text
    ))
    if source == 'hf_loghub':
        for d in re.findall(r'rhost=([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,10})\b', text):
            domains.add(d.replace('.', '[.]'))
    domains = {d for d in domains if d.replace('[.]', '.') not in DOMAIN_WHITELIST}
    cves = set(re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE))
    urls = {u for u in re.findall(r'hxxps?://[^\s\'\"<>]+', text)
            if not any(w.replace('.', '[.]') in u or w in u for w in DOMAIN_WHITELIST)}
    malware_names = set()
    if source == 'mitre_attack':
        malware_names = set(re.findall(r'^([A-Z][A-Za-z0-9_\-\.]+):\s', text, re.MULTILINE))

    parts = []
    if cves:
        parts.append("CVE Identifiers:\n- " + "\n- ".join(sorted(cves)))
    if malware_names:
        parts.append("Malware/Tool Names:\n- " + "\n- ".join(sorted(malware_names)))
    if ips:
        parts.append("IP Addresses:\n- " + "\n- ".join(ip.replace('.', '[.]') for ip in sorted(ips)))
    if domains:
        parts.append("Domains:\n- " + "\n- ".join(sorted(domains)))
    if urls:
        parts.append("URLs:\n- " + "\n- ".join(sorted(list(urls)[:5])))
    if hashes:
        parts.append("File Hashes:\n- " + "\n- ".join(sorted(list(hashes)[:5])))
    return "\n\n".join(parts) if parts else None

# ============================================================
# System Prompt
# ============================================================

SYSTEM_PROMPT = (
    "You are an expert cybersecurity analyst specializing in Text OSINT "
    "and threat intelligence for red team operations. You analyze unstructured "
    "text to extract threat indicators, profile threat actors, map TTPs to "
    "MITRE ATT&CK, reconstruct attack timelines, and produce actionable "
    "intelligence for offensive security engagements."
)

def _msg(user_content, assistant_content, source):
    return {
        "messages": [
            {"role": "system",    "content": SYSTEM_PROMPT},
            {"role": "user",      "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "source": source
    }

# ============================================================
# Source-Specific Instruction Makers
# ============================================================

def make_abusech_instruction(text, record, source):
    threat_type = record.get('threat', 'malware').replace('_', ' ').title()
    date = record.get('date', '')

    prompts = [
        f"A threat intelligence feed flagged this as active malware infrastructure. Analyze the URL and provide an operational assessment:\n\n{text}",
        f"This URL was reported to abuse.ch as a malware distribution point. Extract IOCs and explain its threat relevance:\n\n{text}",
        f"Identify the threat infrastructure in this abuse.ch report and assess its red team relevance:\n\n{text}",
    ]

    iocs = extract_iocs(text, source)
    domain_match = re.search(r'hxxps?://([^/\s\[\]]+(?:\[\.\][^/\s]+)?)', text)
    host = domain_match.group(1) if domain_match else None
    is_ip = bool(re.match(r'[\d\.\[\]]+(?::\d+)?$', host or ''))
    tld = host.split('.')[-1].strip(']').split(':')[0] if host and '.' in host and not is_ip else None

    resp = [
        f"Threat Classification: {threat_type}",
        f"IOC Confidence: {ioc_confidence(source)}",
    ]
    if iocs:
        resp.append(f"Extracted Indicators:\n{iocs}")
    if host:
        if is_ip:
            resp.append(
                f"Infrastructure Analysis: IP-based payload delivery ({host}). "
                f"Direct IP hosting avoids DNS-based detection and blocklists. "
                f"Common in commodity malware loaders targeting Linux/IoT devices (note: .sh script extension)."
            )
        else:
            resp.append(
                f"Infrastructure Analysis: Domain uses .{tld} TLD. "
                f"Abuse.ch listing confirms active malware staging infrastructure. "
                f"High-entropy subdomain or unusual TLD selection is consistent with throwaway delivery domains."
            )
    resp.append(
        "Red Team Context: This represents active attacker-controlled payload staging. "
        "For detection engineering: monitor HTTP requests to newly registered domains with similar TLD patterns. "
        "For adversary emulation: replicate infrastructure naming conventions and TLD selection when building red team payload delivery infrastructure."
    )
    if date:
        resp.append(f"Temporal Note: Reported active {date}. Verify current status before using as a live IOC.")

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_cisa_instruction(text, record, source):
    cve_id = record.get('cve_id', '')
    if not cve_id:
        m = re.search(r'CVE-\d{4}-\d+', text)
        cve_id = m.group(0) if m else 'Unknown CVE'
    vendor  = record.get('vendor', 'Unknown Vendor')
    product = record.get('product', 'Unknown Product')

    prompts = [
        f"Review this CISA Known Exploited Vulnerability and produce a red team operational assessment:\n\n{text}",
        f"This vulnerability is confirmed actively exploited in the wild (CISA KEV). Analyze it from an offensive perspective:\n\n{text}",
        f"As a red team operator, assess the exploitation potential and attack surface relevance of this CISA advisory:\n\n{text}",
    ]

    vuln_type     = infer_vuln_type(text)
    attack_vector = infer_attack_vector(text)
    kill_chain    = infer_kill_chain_phase(text)
    iocs          = extract_iocs(text, source)

    resp = [
        f"Vulnerability: {cve_id} — {vendor} {product}",
        f"Vulnerability Class: {vuln_type}",
        f"Attack Vector: {attack_vector}",
        f"Kill Chain Phase: {kill_chain}",
        "Exploitation Status: CONFIRMED ACTIVE EXPLOITATION — CISA KEV listing means this is weaponized and in use by threat actors. Treat as a high-priority attack path.",
    ]

    action_m = re.search(r'[Rr]equired action[:\s]+(.+?)(?:\.|$)', text)
    if action_m:
        resp.append(f"Required Remediation: {action_m.group(1).strip()}")

    resp.append(
        f"Red Team Application: Enumerate {vendor} {product} deployments on target scope via Shodan "
        f"(query: product:\"{product}\") or Censys. Cross-reference with passive recon asset inventory. "
        f"If unpatched instances exist, this is a high-confidence initial access or privilege escalation path."
    )
    resp.append(
        "OSINT Pivot: Search GitHub for PoC repositories (query: CVE-ID + PoC), check ExploitDB, "
        "and monitor Telegram security channels (cveNotify) for weaponized exploit availability."
    )
    if iocs:
        resp.append(f"Technical Indicators:\n{iocs}")

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_cve_instruction(text, record, source):
    cve_id = record.get('cve_id', '')
    if not cve_id:
        m = re.search(r'CVE-\d{4}-\d+', text)
        cve_id = m.group(0) if m else 'Unknown CVE'

    prompts = [
        f"Assess this CVE from a red team offensive operations perspective:\n\n{text}",
        f"Analyze this vulnerability description and identify how a red team operator would leverage it:\n\n{text}",
        f"What does this vulnerability enable for an attacker, and how would you locate vulnerable instances during reconnaissance?\n\n{text}",
        f"Extract exploitation context from this CVE description and assess its relevance to an active engagement:\n\n{text}",
    ]

    vuln_type     = infer_vuln_type(text)
    attack_vector = infer_attack_vector(text)
    kill_chain    = infer_kill_chain_phase(text)
    techniques    = extract_mitre_techniques(text)
    iocs          = extract_iocs(text, source)

    capability_map = {
        'Remote Code Execution':         'Full remote compromise — enables initial foothold without credentials. Highest-value exploit class.',
        'Privilege Escalation':          'Elevates attacker from low-privilege to system/root — critical link in post-exploitation chain.',
        'Authentication Bypass':         'Access protected resources without valid credentials — enables initial access or lateral movement.',
        'Information Disclosure':        'Leaks credentials, internal paths, or config data — feeds subsequent stages of the attack.',
        'SQL Injection':                 'Database access and potential credential extraction; possible RCE via xp_cmdshell or INTO OUTFILE.',
        'Command Injection':             'OS-level code execution — functionally equivalent to RCE in most deployment contexts.',
        'Memory Corruption / Buffer Overflow': 'Potential code execution via memory corruption — often requires chaining with info-leak.',
        'Server-Side Request Forgery':   'Forces server to make internal requests — enables cloud metadata theft, internal port scan, SSRF-to-RCE chains.',
    }
    capability = next(
        (v for k, v in capability_map.items() if k in vuln_type),
        'Grants attacker capability within the context of the affected component. Review CVSS vector for severity.'
    )

    resp = [
        f"Vulnerability: {cve_id}",
        f"Vulnerability Class: {vuln_type}",
        f"Attack Vector: {attack_vector}",
        f"Kill Chain Phase: {kill_chain}",
        f"Attacker Capability: {capability}",
    ]
    if techniques:
        resp.append(f"MITRE ATT&CK Techniques: {', '.join(techniques)}")
    resp.append(
        "Reconnaissance Pivot: To identify vulnerable instances during pre-exploitation recon, "
        "query Shodan/Censys for the affected product/version. Check certificate transparency logs for subdomains. "
        "Cross-reference target technology stack (job postings, GitHub repos, HTTP headers) against affected versions."
    )
    if iocs:
        resp.append(f"Technical Indicators:\n{iocs}")

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_mitre_instruction(text, record, source):
    mitre_type = record.get('type', 'technique')
    techniques = extract_mitre_techniques(text)
    malware    = extract_malware_families(text)
    kill_chain = infer_kill_chain_phase(text)

    if mitre_type == 'malware':
        prompts = [
            f"Profile this malware or red team tool for adversary emulation planning:\n\n{text}",
            f"Analyze this malware/tool entry from MITRE ATT&CK and extract TTPs for purple team simulation:\n\n{text}",
        ]
    elif mitre_type == 'group':
        prompts = [
            f"Build a threat actor profile from this MITRE ATT&CK group entry for adversary emulation:\n\n{text}",
            f"Analyze this threat actor's known TTPs and targeting patterns for red team engagement planning:\n\n{text}",
        ]
    else:
        prompts = [
            f"Explain how this MITRE ATT&CK technique manifests in threat intelligence text and how red teamers apply it:\n\n{text}",
            f"From a Text OSINT perspective, how would an analyst identify this technique from threat actor communications?\n\n{text}",
            f"Map this ATT&CK technique to its real-world indicators and red team implementation context:\n\n{text}",
        ]

    resp = [f"MITRE ATT&CK Entry Type: {mitre_type.title()}"]
    if techniques:
        resp.append(f"Technique IDs: {', '.join(techniques)}")
    if malware:
        resp.append(f"Associated Tools/Malware: {', '.join(malware)}")
    resp.append(f"Kill Chain Phase: {kill_chain}")

    if mitre_type not in ('malware', 'group'):
        resp.append(
            "Text OSINT Indicators: When analyzing threat actor communications, "
            "this technique appears as references to specific tools, operational steps, or infrastructure patterns "
            "in forum posts, paste sites, and dark web listings. Technique-specific vocabulary serves as an attribution signal."
        )

    resp.append(
        "Red Team Application: Use this entry to structure adversary emulation scenarios. "
        "Cross-reference with ATT&CK Navigator to identify which threat actor groups use this technique, "
        "then build emulation profiles matching a specific group's known TTP chain."
    )
    resp.append(
        "Detection Context: Understanding how defenders detect this technique informs red team stealth requirements. "
        "Consult Sigma rules and MITRE's detection guidance to assess defender visibility for this TTP."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_threatfox_instruction(text, record, source):
    malware_family = record.get('malware', 'Unknown Malware')
    ioc_type       = record.get('ioc_type', 'indicator')

    prompts = [
        f"Analyze this ThreatFox IOC report and assess the malware infrastructure for red team and defensive context:\n\n{text}",
        f"Extract operational intelligence from this ThreatFox C2 indicator report:\n\n{text}",
        f"Assess the threat infrastructure described in this ThreatFox report and identify pivot opportunities:\n\n{text}",
    ]

    iocs   = extract_iocs(text, source)
    malware = extract_malware_families(text)

    resp = [
        f"Malware Family: {malware_family}",
        f"IOC Type: {ioc_type}",
        f"IOC Confidence: {ioc_confidence(source)}",
    ]
    if iocs:
        resp.append(f"Extracted Indicators:\n{iocs}")

    is_c2 = any(k in (malware_family + text).lower() for k in ['cobalt', 'c2', 'c&c', 'sliver', 'havoc', 'brute ratel', 'beacon'])
    if is_c2:
        resp.append(
            "C2 Framework Analysis: This IOC represents a command-and-control endpoint. "
            "Detection approach: look for irregular beacon intervals, large HTTP POSTs to suspicious user agents, "
            "or long-duration low-bandwidth connections. JA3/JA3S fingerprinting can identify C2 frameworks at the TLS layer."
        )

    resp.append(
        "Red Team Infrastructure Awareness: IOCs like this reach ThreatFox within hours of detection. "
        "When building red team C2 infrastructure, use domain fronting, legitimate cloud provider hosting, "
        "and short-lived rotated endpoints to minimize IOC exposure. Categorized domains evade proxy filtering."
    )
    resp.append(
        "OSINT Pivot: Search VirusTotal, Shodan, and Censys with this IOC to map the broader campaign infrastructure. "
        "A single C2 server often links to an entire campaign through shared TLS certificates, ASN, or hosting patterns."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_log_instruction(text, record, source):
    log_type = record.get('log_type', 'system')

    prompts = [
        f"Analyze this system log entry and reconstruct the attacker's activity:\n\n{text}",
        f"From a red team perspective, what attack is represented in this log entry and what did the attacker accomplish?\n\n{text}",
        f"As a threat hunter, what does this log entry reveal about attacker behavior and technique?\n\n{text}",
        f"Identify the attack pattern in this log excerpt and map it to the kill chain:\n\n{text}",
    ]

    iocs       = extract_iocs(text, source)
    kill_chain = infer_kill_chain_phase(text)

    log_patterns = [
        ('authentication failure',  'Credential Attack',         'Brute force or credential stuffing detected. Multiple auth failures from a single source indicate an automated attack.'),
        ('failed password',         'Failed Authentication',     'Password-based auth failure. Monitor for a subsequent success event — indicates potential credential compromise.'),
        ('invalid user',            'Username Enumeration',      'Attacker probing for valid usernames as a precursor to targeted credential attacks.'),
        ('session opened',          'Successful Authentication', 'Session established. If preceded by auth failures, this may indicate successful brute force completion.'),
        ('sudo',                    'Privilege Action',          'Sudo invocation detected. Check for unauthorized privilege escalation or lateral movement via sudo misconfigurations.'),
        ('connection from',         'Inbound Connection',        'Inbound connection logged. Correlate source IP with threat intelligence feeds.'),
        ('command not found',       'Post-Exploitation Recon',   'Attacker executing commands on a compromised system. Missing tools indicate initial recon phase.'),
    ]

    event_type   = 'System Event'
    event_detail = 'Log entry captured system activity. Correlate with adjacent events for full attack picture.'
    t_lower = text.lower()
    for pattern, etype, detail in log_patterns:
        if pattern in t_lower:
            event_type   = etype
            event_detail = detail
            break

    resp = [
        f"Log Source: {log_type} system logs",
        f"Event Classification: {event_type}",
        f"Kill Chain Phase: {kill_chain}",
        f"Analysis: {event_detail}",
    ]
    if iocs:
        resp.append(f"Indicators:\n{iocs}")
    resp.append(
        "Red Team Context: This log pattern is generated during the "
        + kill_chain + " phase of an engagement. "
        "Operators should understand this detection footprint — these events will trigger SIEM alerts in mature environments. "
        "Consider timing, volume, and source IP rotation to reduce detection probability."
    )
    resp.append(
        "Text OSINT Value: Log entries exposed in public bug reports, developer forums, or misconfigured log endpoints "
        "reveal internal hostnames, IP ranges, usernames, and software versions — all valuable for pre-exploitation reconnaissance."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_cti_report_instruction(text, record, source):
    actor      = extract_threat_actor(text)
    malware    = extract_malware_families(text)
    techniques = extract_mitre_techniques(text)
    kill_chain = infer_kill_chain_phase(text)
    iocs       = extract_iocs(text, source)

    source_labels = {
        'otx':            'AlienVault OTX threat intelligence report',
        'hf_cti':         'cyber threat intelligence article',
        'bleepingcomputer': 'security news report',
    }
    label = source_labels.get(source, 'threat intelligence report')

    prompts = [
        f"Produce a structured threat intelligence assessment from this {label}:\n\n{text}",
        f"Analyze this {label} and extract actionable intelligence for a red team engagement:\n\n{text}",
        f"Extract threat actor TTPs, infrastructure indicators, and targeting patterns from this report:\n\n{text}",
        f"As a threat intelligence analyst, summarize the key findings from this {label} with red team context:\n\n{text}",
    ]

    resp = [
        f"Threat Actor: {actor}" if actor else "Threat Actor: Not explicitly named — attribution requires cross-referencing TTPs with known actor profiles",
    ]
    if malware:
        resp.append(f"Tools/Malware Identified: {', '.join(malware)}")
    resp.append(f"Kill Chain Coverage: {kill_chain}")
    if techniques:
        resp.append(f"MITRE ATT&CK Techniques: {', '.join(techniques)}")
    resp.append(f"Intelligence Confidence: {ioc_confidence(source)}")

    if iocs:
        resp.append(f"Extracted Indicators:\n{iocs}")
    else:
        resp.append(
            "Technical Indicators: No machine-parseable IOCs extracted. "
            "This report contains narrative/contextual intelligence — valuable for TTP profiling and adversary emulation even without specific IOCs."
        )

    resp.append(
        "Red Team Application: This intelligence informs adversary emulation by identifying the TTPs, tools, "
        "and infrastructure patterns used by real threat actors. "
        "Incorporate these findings into engagement planning to simulate a specific threat actor's tradecraft "
        "rather than using generic attack paths."
    )
    if actor or malware:
        pivot_parts = []
        if actor:
            pivot_parts.append(f"threat actor '{actor}'")
        if malware:
            pivot_parts.append(f"tools: {', '.join(malware[:2])}")
        resp.append(
            f"OSINT Pivot: Search for additional intelligence on {' and '.join(pivot_parts)} "
            "in MITRE ATT&CK Groups, VirusTotal Graph, Mandiant/Crowdstrike public reports, and MISP communities."
        )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_fenrir_instruction(text, record, source):
    q_idx = text.find('?')
    if 20 < q_idx < len(text) * 0.45:
        question = text[:q_idx + 1].strip()
        answer   = text[q_idx + 1:].strip()
        answer   = re.sub(r'^#{1,4}[^\n]+\n', '', answer, flags=re.MULTILINE)
        answer   = re.sub(r'\*\*(.*?)\*\*', r'\1', answer)
    else:
        parts    = text.split('\n\n', 1)
        question = parts[0].strip()
        answer   = parts[1].strip() if len(parts) > 1 else text

    if len(answer) < 50:
        answer = text

    techniques = extract_mitre_techniques(text)
    malware    = extract_malware_families(text)
    kill_chain = infer_kill_chain_phase(text)

    user_content = f"Red team knowledge query: {question[:2000]}"

    resp_parts = [answer[:2500].strip()]
    if techniques:
        resp_parts.append(f"MITRE ATT&CK Mapping: {', '.join(techniques)}")
    if kill_chain != 'Multi-phase / Unclassified':
        resp_parts.append(f"Kill Chain Phase: {kill_chain}")
    if malware:
        resp_parts.append(f"Relevant Tools: {', '.join(malware[:3])}")

    return _msg(user_content, "\n\n".join(resp_parts), source)


def make_cyberv1_instruction(text, record, source):
    q_idx = text.find('?')
    if 10 < q_idx < len(text) * 0.5:
        question = text[:q_idx + 1].strip()
        answer   = text[q_idx + 1:].strip()
    else:
        mid       = len(text) // 3
        split_idx = text.find('. ', mid)
        question  = text[:split_idx + 1].strip() if split_idx > 0 else text[:200].strip()
        answer    = text[split_idx + 1:].strip() if split_idx > 0 else text[200:].strip()

    if len(answer) < 30:
        answer = text

    techniques = extract_mitre_techniques(text)
    kill_chain = infer_kill_chain_phase(text)

    prompts = [
        f"Explain this cybersecurity concept with a focus on red team and Text OSINT applications:\n\n{question}",
        f"Answer this security question and explain how it applies to offensive security operations:\n\n{question}",
    ]

    resp_parts = [answer[:2500].strip()]
    if techniques:
        resp_parts.append(f"MITRE ATT&CK: {', '.join(techniques)}")
    if kill_chain != 'Multi-phase / Unclassified':
        resp_parts.append(f"Operational Context: {kill_chain}")

    return _msg(random.choice(prompts), "\n\n".join(resp_parts), source)


def make_telegram_instruction(text, record, source):
    channel = record.get('channel', 'security channel')
    date    = record.get('date', '')

    prompts = [
        f"Analyze this threat intelligence message from a Telegram security channel and extract operational intelligence:\n\n{text}",
        f"Perform Text OSINT analysis on this Telegram security alert and provide red team context:\n\n{text}",
        f"A security Telegram channel posted this message. Extract IOCs, assess the threat, and advise on engagement implications:\n\n{text}",
    ]

    cves       = sorted(set(re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)))
    iocs       = extract_iocs(text, source)
    malware    = extract_malware_families(text)
    kill_chain = infer_kill_chain_phase(text)

    resp = [f"Source: Telegram '{channel}'" + (f" ({date})" if date else '')]
    if cves:
        resp.append(f"CVEs Referenced: {', '.join(cves)}")
    if malware:
        resp.append(f"Malware/Tools Mentioned: {', '.join(malware)}")
    resp.append(f"Kill Chain Phase: {kill_chain}")

    if any(k in text.lower() for k in ['poc', 'proof of concept', 'weaponized', 'active exploitation', 'exploit available']):
        resp.append(
            "Exploitation Status: Message indicates PoC or active exploitation is available. "
            "Treat referenced CVEs as HIGH PRIORITY. "
            "Search GitHub (query: CVE-ID PoC) and ExploitDB immediately. "
            "Check Shodan for exposed instances in target scope."
        )

    if iocs:
        resp.append(f"Technical Indicators:\n{iocs}")

    resp.append(
        "OPSEC Intelligence: Telegram security channels are monitored by both defenders and threat actors. "
        "Red teams should track these channels to understand current defender awareness. "
        "Prioritize TTPs that are not yet widely discussed — they face less mature detection coverage."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_virustotal_instruction(text, record, source):
    prompts = [
        f"Review this VirusTotal analysis comment and extract actionable threat intelligence:\n\n{text}",
        f"Analyze this malware analysis commentary and identify key threat indicators for operational use:\n\n{text}",
    ]

    iocs   = extract_iocs(text, source)
    malware = extract_malware_families(text)

    t_lower = text.lower()
    if 'malware' in t_lower or 'malicious' in t_lower:
        verdict = 'Malicious'
    elif 'clean' in t_lower or 'benign' in t_lower:
        verdict = 'Clean/Benign'
    elif 'suspicious' in t_lower:
        verdict = 'Suspicious'
    else:
        verdict = 'Unclassified'

    score_m = re.search(r'(\d+)%', text)

    resp = [f"Analysis Verdict: {verdict}" + (f" (Score: {score_m.group(0)})" if score_m else '')]
    if malware:
        resp.append(f"Malware Classification: {', '.join(malware)}")
    if iocs:
        resp.append(f"Technical Indicators:\n{iocs}")
    resp.append(
        "VirusTotal Context: Community comments supplement automated AV detection. "
        "High engagement (votes, comments) increases confidence in classification. "
        "Red team note: before deploying custom payloads, check VT detection rate — "
        "aim for <5/72 detections for operational payloads to avoid early-stage detection."
    )
    resp.append(
        "OSINT Pivot: From a VT file hash, pivot to: related samples (behavioral clustering), "
        "associated network indicators (C2 infrastructure), and threat actor attribution via behavioral graph."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_hackernews_instruction(text, record, source):
    prompts = [
        f"Extract security-relevant intelligence from this technical community discussion:\n\n{text}",
        f"Analyze this Hacker News comment for cybersecurity insights applicable to red team operations:\n\n{text}",
        f"What OSINT value can be extracted from this technical discussion for threat intelligence purposes?\n\n{text}",
    ]

    techniques = extract_mitre_techniques(text)
    malware    = extract_malware_families(text)
    kill_chain = infer_kill_chain_phase(text)
    iocs       = extract_iocs(text, source)

    resp = []
    if kill_chain != 'Multi-phase / Unclassified':
        resp.append(f"Security Relevance: {kill_chain} phase discussion")
    if malware:
        resp.append(f"Tools/Techniques Referenced: {', '.join(malware)}")
    if techniques:
        resp.append(f"MITRE ATT&CK References: {', '.join(techniques)}")
    if iocs:
        resp.append(f"Technical Indicators:\n{iocs}")
    if not resp:
        resp.append("Security Relevance: General technical discussion with indirect security context.")

    resp.append(
        "Community Intelligence Value: Technical forums like Hacker News surface novel techniques and tool capabilities "
        "before formal disclosure. Monitoring provides early signals on emerging attack methods and defender awareness."
    )
    resp.append(
        "Red Team Application: Community discussions reveal which TTPs are well-understood by defenders "
        "(high detection probability) versus techniques that remain niche. "
        "Less-discussed techniques offer better operational stealth in mature security environments."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_wikipedia_instruction(text, record, source):
    prompts = [
        f"Summarize this security concept and explain its relevance to red team operations and Text OSINT:\n\n{text}",
        f"From an offensive security perspective, what is operationally important in this security knowledge article?\n\n{text}",
        f"Extract key concepts from this text and map them to red team TTPs and OSINT applications:\n\n{text}",
    ]

    techniques = extract_mitre_techniques(text)
    malware    = extract_malware_families(text)
    kill_chain = infer_kill_chain_phase(text)

    first_sentence_end = text.find('.')
    summary = text[:first_sentence_end + 1] if first_sentence_end > 0 else text[:200]

    resp = [f"Concept Summary: {summary}"]
    if kill_chain != 'Multi-phase / Unclassified':
        resp.append(f"Kill Chain Relevance: {kill_chain}")
    if techniques:
        resp.append(f"MITRE ATT&CK Techniques: {', '.join(techniques)}")
    if malware:
        resp.append(f"Related Tools/Malware: {', '.join(malware)}")
    resp.append(
        "Text OSINT Application: Understanding this concept enables accurate identification when it appears in "
        "threat actor communications, forum posts, or technical documents. "
        "Terminology and concept references in text signal threat actor technical sophistication — "
        "a key attribution indicator in stylometric analysis."
    )
    resp.append(
        "Red Team Knowledge: This foundational concept informs attack planning, technique selection, "
        "and the ability to communicate using precise technical language — "
        "critical for building realistic threat actor personas and credible social engineering pretexts."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


# ============================================================
# Phase 2 Source Instruction Makers
# ============================================================

def make_misp_galaxy_instruction(text, record, source):
    cluster_type = record.get('cluster_type', 'threat_actor')
    name         = record.get('name', '')

    if cluster_type == 'threat_actor':
        prompts = [
            f"Build a threat actor intelligence profile from this MISP Galaxy entry for adversary emulation:\n\n{text}",
            f"Analyze this threat actor profile and extract attribution indicators for a red team engagement:\n\n{text}",
            f"From a Text OSINT perspective, what signals in this threat actor description enable attribution?\n\n{text}",
        ]
    elif cluster_type in ('malware', 'malware_detailed', 'ransomware'):
        prompts = [
            f"Profile this malware family from the MISP Galaxy for adversary emulation and detection:\n\n{text}",
            f"Analyze this malware description and identify its operational characteristics for red team use:\n\n{text}",
        ]
    else:
        prompts = [
            f"Analyze this attack tool profile and explain its red team and threat intelligence relevance:\n\n{text}",
            f"Extract operational intelligence from this MISP Galaxy tool entry:\n\n{text}",
        ]

    actor      = extract_threat_actor(text)
    malware    = extract_malware_families(text)
    techniques = extract_mitre_techniques(text)
    kill_chain = infer_kill_chain_phase(text)
    iocs       = extract_iocs(text, source)

    resp = [f"Entry Type: {cluster_type.replace('_', ' ').title()}"]
    if name:
        resp.append(f"Name: {name}")
    if actor and actor != name:
        resp.append(f"Related Threat Actor: {actor}")
    if malware:
        resp.append(f"Associated Malware/Tools: {', '.join(malware)}")
    if techniques:
        resp.append(f"MITRE ATT&CK Techniques: {', '.join(techniques)}")
    resp.append(f"Kill Chain Relevance: {kill_chain}")
    if iocs:
        resp.append(f"Technical Indicators:\n{iocs}")
    resp.append(
        "Attribution Value: MISP Galaxy entries represent community-verified threat intelligence. "
        "Synonyms and aliases are critical for cross-source attribution — a threat actor may appear "
        "under different names across vendor reports. Always check all known aliases when pivoting."
    )
    resp.append(
        "Red Team Application: Use this profile to emulate the identified threat actor's tradecraft. "
        "Match their known tools, techniques, and targeting patterns to build a realistic adversary emulation plan."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_ghsa_instruction(text, record, source):
    severity = record.get('severity', 'UNKNOWN')
    cve_id   = record.get('cve_id', '')
    ghsa_id  = record.get('ghsa_id', '')

    prompts = [
        f"Assess this GitHub Security Advisory from a red team and supply chain attack perspective:\n\n{text}",
        f"Analyze this package vulnerability advisory and determine its offensive relevance:\n\n{text}",
        f"A software supply chain vulnerability has been disclosed. Assess its red team implications:\n\n{text}",
    ]

    vuln_type  = infer_vuln_type(text)
    kill_chain = infer_kill_chain_phase(text)
    malware    = extract_malware_families(text)
    iocs       = extract_iocs(text, source)

    resp = []
    if ghsa_id:
        resp.append(f"Advisory: {ghsa_id}" + (f" / {cve_id}" if cve_id else ''))
    resp.append(f"Severity: {severity}")
    resp.append(f"Vulnerability Class: {vuln_type}")
    resp.append(f"Kill Chain Phase: {kill_chain}")

    # Extract package info from text
    pkg_match = re.search(r'Affected Package:\s*([^\n]+)', text)
    if pkg_match:
        resp.append(f"Supply Chain Target: {pkg_match.group(1).strip()}")
        resp.append(
            "Supply Chain Attack Surface: This vulnerability exists in a software package dependency. "
            "Attack vector: compromise the package registry entry, inject malicious code into a version, "
            "or exploit unpatched instances. Identify targets using this package via dependency scanners "
            "or public package download statistics."
        )

    resp.append(
        "Red Team Application: Package-level vulnerabilities enable supply chain attack scenarios. "
        "During pre-engagement recon, scan target's public repos (GitHub, GitLab) for this dependency. "
        "Check package.json, requirements.txt, go.mod, pom.xml for affected versions. "
        "Unpatched package = high-confidence exploitation path in CI/CD or production environments."
    )
    resp.append(
        "OSINT Pivot: Search GitHub code for this package usage: "
        f"'grep -r \"{pkg_match.group(1).strip().split()[0] if pkg_match else 'package'}\"' "
        "in target's public repositories. Cross-reference with Snyk, OSV.dev, and Deps.dev for exposure mapping."
    )
    if iocs:
        resp.append(f"Technical Indicators:\n{iocs}")

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_exploitdb_instruction(text, record, source):
    etype    = record.get('exploit_type', '')
    platform = record.get('platform', '')

    prompts = [
        f"Analyze this Exploit-DB entry and assess its offensive utility for a red team engagement:\n\n{text}",
        f"From a red team operator's perspective, evaluate this publicly available exploit:\n\n{text}",
        f"Assess the exploitation potential and targeting context of this public exploit:\n\n{text}",
    ]

    vuln_type  = infer_vuln_type(text)
    kill_chain = infer_kill_chain_phase(text)
    techniques = extract_mitre_techniques(text)
    cves       = re.findall(r'CVE-\d{4}-\d+', text)

    type_map = {
        'remote':  'Initial Access / Exploitation',
        'local':   'Privilege Escalation',
        'dos':     'Impact / Disruption',
        'webapps': 'Initial Access (Web)',
    }
    phase = type_map.get(etype.lower(), kill_chain)

    resp = [
        f"Exploit Type: {etype.title() if etype else 'Unclassified'}",
        f"Target Platform: {platform if platform else 'Not specified'}",
        f"Vulnerability Class: {vuln_type}",
        f"Kill Chain Phase: {phase}",
    ]
    if cves:
        resp.append(f"CVE References: {', '.join(cves)}")
    if techniques:
        resp.append(f"MITRE ATT&CK: {', '.join(techniques)}")
    resp.append(
        f"Operational Assessment: This is a {'verified' if 'verified' in text.lower() else 'public'} "
        f"exploit for {platform if platform else 'the target platform'}. "
        f"{'Remote exploits are the highest-value — no prior access required.' if etype == 'remote' else ''}"
        f"{'Local exploits require an existing foothold — use as a privilege escalation step.' if etype == 'local' else ''}"
        f"{'Web application exploits are relevant when the target runs the affected software stack.' if etype == 'webapps' else ''}"
    )
    resp.append(
        "Red Team Application: Search Exploit-DB, GitHub, and Metasploit modules for this exploit. "
        "Verify target version during recon before attempting exploitation. "
        "Cross-reference with Shodan/Censys to find exposed instances."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_atomic_instruction(text, record, source):
    tech_id = record.get('technique_id', '')

    prompts = [
        f"Analyze this Atomic Red Team test procedure and explain how a red team operator would execute it:\n\n{text}",
        f"This is a documented adversary technique test. Assess its detection footprint and red team application:\n\n{text}",
        f"From both offensive and defensive perspectives, analyze this ATT&CK technique test procedure:\n\n{text}",
    ]

    malware    = extract_malware_families(text)
    kill_chain = infer_kill_chain_phase(text)
    iocs       = extract_iocs(text, source)

    resp = []
    if tech_id:
        resp.append(f"ATT&CK Technique: {tech_id}")
    resp.append(f"Kill Chain Phase: {kill_chain}")

    # Extract platform from text
    platform_match = re.search(r'Supported Platforms:\s*([^\n]+)', text)
    if platform_match:
        resp.append(f"Target Platforms: {platform_match.group(1).strip()}")

    exec_match = re.search(r'Execution Method:\s*([^\n]+)', text)
    if exec_match:
        resp.append(f"Execution Method: {exec_match.group(1).strip()}")

    if malware:
        resp.append(f"Associated Tools: {', '.join(malware)}")
    if iocs:
        resp.append(f"Indicators:\n{iocs}")

    resp.append(
        "Red Team Execution Context: This atomic test represents a validated, real-world implementation "
        "of the ATT&CK technique. Red team operators can adapt this procedure for authorized engagements. "
        "Review prerequisites and cleanup steps in the full atomic definition before executing."
    )
    resp.append(
        "Detection Footprint: Each atomic test generates specific log events and artifacts. "
        "Understanding what this procedure produces (process creation logs, registry changes, "
        "network connections, file system artifacts) allows red teams to assess their detection exposure "
        "and defenders to write targeted detection rules."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_security_news_instruction(text, record, source):
    """For mandiant_blog and sans_isc."""
    source_labels = {
        'mandiant_blog': 'Mandiant threat intelligence report',
        'sans_isc':      'SANS Internet Storm Center security diary',
    }
    label = source_labels.get(source, 'security intelligence report')

    prompts = [
        f"Produce a structured threat intelligence assessment from this {label}:\n\n{text}",
        f"Extract actionable red team intelligence from this {label}:\n\n{text}",
        f"Analyze this {label} and identify TTPs, actors, and red team relevance:\n\n{text}",
    ]

    actor      = extract_threat_actor(text)
    malware    = extract_malware_families(text)
    techniques = extract_mitre_techniques(text)
    kill_chain = infer_kill_chain_phase(text)
    iocs       = extract_iocs(text, source)

    resp = [
        f"Source: {label}",
        f"Threat Actor: {actor}" if actor else "Threat Actor: Not explicitly named",
    ]
    if malware:
        resp.append(f"Tools/Malware: {', '.join(malware)}")
    if techniques:
        resp.append(f"MITRE ATT&CK: {', '.join(techniques)}")
    resp.append(f"Kill Chain: {kill_chain}")
    if iocs:
        resp.append(f"Indicators:\n{iocs}")
    else:
        resp.append(
            "Technical Indicators: No machine-parseable IOCs extracted. "
            "Report contains narrative intelligence — valuable for TTP profiling and campaign context."
        )
    resp.append(
        "Red Team Application: Use this intelligence to understand current threat actor activity "
        "and emulate realistic TTPs in authorized engagements. "
        "Cross-reference with MITRE ATT&CK and your engagement scope."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


def make_arxiv_instruction(text, record, source):
    prompts = [
        f"Extract key security concepts and red team applications from this academic security research paper:\n\n{text}",
        f"Summarize this security research paper and explain its practical implications for offensive security:\n\n{text}",
        f"What does this academic security research reveal about attack techniques or defensive gaps?\n\n{text}",
    ]

    techniques = extract_mitre_techniques(text)
    malware    = extract_malware_families(text)
    kill_chain = infer_kill_chain_phase(text)

    # Extract paper title (first line)
    lines = text.split('\n', 1)
    title = lines[0].strip() if lines else ''

    resp = []
    if title:
        resp.append(f"Paper: {title}")
    if kill_chain != 'Multi-phase / Unclassified':
        resp.append(f"Security Domain: {kill_chain}")
    if techniques:
        resp.append(f"MITRE ATT&CK Relevance: {', '.join(techniques)}")
    if malware:
        resp.append(f"Referenced Tools/Malware: {', '.join(malware)}")

    resp.append(
        "Research Value: Academic papers in cs.CR represent peer-reviewed security knowledge. "
        "Novel attack techniques described in papers often precede real-world weaponization by months. "
        "Monitoring arXiv cs.CR provides early warning of emerging attack capabilities."
    )
    resp.append(
        "Red Team Application: Academic research reveals attack primitives that may not yet have "
        "commercial exploit implementations. Understanding the theoretical basis of attacks enables "
        "red teams to develop novel techniques beyond commodity tooling."
    )
    resp.append(
        "Text OSINT Relevance: Academic writing style, citation patterns, and institutional affiliations "
        "in security papers can be used for attribution — identifying which research groups or "
        "nation-state-affiliated institutions are developing specific offensive capabilities."
    )

    return _msg(random.choice(prompts), "\n\n".join(resp), source)


# ============================================================
# Instruction Dispatcher
# ============================================================

INSTRUCTION_DISPATCH = {
    'abusech':               make_abusech_instruction,
    'cisa_kev':              make_cisa_instruction,
    'cve':                   make_cve_instruction,
    'mitre_attack':          make_mitre_instruction,
    'threatfox':             make_threatfox_instruction,
    'hf_loghub':             make_log_instruction,
    'otx':                   make_cti_report_instruction,
    'hf_cti':                make_cti_report_instruction,
    'bleepingcomputer':      make_cti_report_instruction,
    'hf_fenrir':             make_fenrir_instruction,
    'hf_cyber_v1':           make_cyberv1_instruction,
    'telegram':              make_telegram_instruction,
    'virustotal_comments':   make_virustotal_instruction,
    'hf_hackernews':         make_hackernews_instruction,
    'hf_wikipedia_security': make_wikipedia_instruction,
    # Phase 2 sources
    'misp_galaxy':           make_misp_galaxy_instruction,
    'ghsa':                  make_ghsa_instruction,
    'exploitdb':             make_exploitdb_instruction,
    'atomic_red_team':       make_atomic_instruction,
    'mandiant_blog':         make_security_news_instruction,
    'sans_isc':              make_security_news_instruction,
    'arxiv_security':        make_arxiv_instruction,
}

def make_instruction(text, source='', record=None):
    record = record or {}
    fn = INSTRUCTION_DISPATCH.get(source)
    if fn:
        return fn(text, record, source)
    iocs = extract_iocs(text, source)
    return _msg(
        f"Analyze the following cybersecurity text and extract threat intelligence:\n\n{text}",
        iocs or "No explicit IOCs identified. Text contains contextual threat intelligence requiring analyst interpretation.",
        source
    )

# ============================================================
# Schema Mapper
# ============================================================

def extract_raw_text(record, source):
    for key in ['text', 'description', 'message', 'content', 'summary', 'body']:
        val = record.get(key)
        if val and str(val).strip():
            return str(val).strip()
    return ''

# ============================================================
# Main Pipeline
# ============================================================

def process_file(filename, lsh_strict, lsh_loose, seen_exact, dry_run=False, sample_size=1000):
    source = filename.replace('.jsonl', '')
    path   = f"{RAW}/{filename}"
    if not os.path.exists(path):
        return []

    max_records = DOWNSAMPLE.get(filename)
    results     = []
    stats = {'total': 0, 'dropped_short': 0, 'dropped_rejected': 0,
             'dropped_exact_dup': 0, 'dropped_fuzzy_dup': 0, 'truncated': 0, 'passed': 0}

    log.info(f"Processing {filename}")

    records = []
    with open(path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if dry_run and i >= sample_size:
                break
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    if max_records and len(records) > max_records and not dry_run:
        random.seed(42)
        records = random.sample(records, max_records)
        log.info(f"  Downsampled to {max_records:,} records")

    for record in records:
        stats['total'] += 1

        text = extract_raw_text(record, source)
        if not text:
            stats['dropped_short'] += 1
            continue

        original_len  = len(text)
        text_cleaned  = clean_text(text, source=source)

        if not filter_record(text_cleaned, source=source):
            if text_cleaned.lower().startswith('rejected reason:'):
                stats['dropped_rejected'] += 1
            else:
                stats['dropped_short'] += 1
            continue

        if len(text_cleaned) < original_len and original_len > 4096:
            stats['truncated'] += 1

        exact_hash = hashlib.md5(text_cleaned.encode()).hexdigest()
        if exact_hash in seen_exact:
            stats['dropped_exact_dup'] += 1
            continue
        seen_exact.add(exact_hash)

        lsh = lsh_loose if source in ('hf_loghub', 'threatfox', 'abusech') else lsh_strict
        mh  = make_minhash(text_cleaned)
        if lsh.query(mh):
            stats['dropped_fuzzy_dup'] += 1
            continue
        lsh.insert(exact_hash, mh)

        instruction = make_instruction(text_cleaned, source=source, record=record)
        results.append(instruction)
        stats['passed'] += 1

    log.info(
        f"  Total: {stats['total']:,}  Passed: {stats['passed']:,}  "
        f"Dropped: short={stats['dropped_short']:,} rejected={stats['dropped_rejected']:,} "
        f"exact_dup={stats['dropped_exact_dup']:,} fuzzy_dup={stats['dropped_fuzzy_dup']:,}"
    )
    return results


def run(dry_run=False):
    mode = "DRY-RUN (1000 records/file)" if dry_run else "FULL PIPELINE"
    log.info("=" * 60)
    log.info(f"CLEAN PIPELINE v2.0 — {mode}")
    log.info("=" * 60)

    lsh_strict = MinHashLSH(threshold=0.80, num_perm=64)
    lsh_loose  = MinHashLSH(threshold=0.95, num_perm=64)
    seen_exact = set()
    all_results = []

    for filename in sorted(f for f in os.listdir(RAW) if f.endswith('.jsonl')):
        results = process_file(
            filename, lsh_strict, lsh_loose, seen_exact,
            dry_run=dry_run, sample_size=1000
        )
        all_results.extend(results)

    random.seed(42)
    random.shuffle(all_results)

    suffix   = "_dryrun" if dry_run else ""
    out_path = f"{OUT}/v2_0_cleaned{suffix}.jsonl"
    with open(out_path, 'w', encoding='utf-8') as f:
        for rec in all_results:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')

    log.info("=" * 60)
    log.info(f"Output : {out_path}")
    log.info(f"Records: {len(all_results):,}")
    log.info("=" * 60)


if __name__ == "__main__":
    import sys
    run(dry_run='--dry-run' in sys.argv)
