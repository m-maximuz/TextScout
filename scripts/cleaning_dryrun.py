import json, os, re, logging
from pathlib import Path

RAW     = os.path.expanduser("~/osint-project/data/01_raw")
LOG_DIR = os.path.expanduser("~/osint-project/logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/cleaning_dryrun.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ---- Cleaning Functions ----
def remove_html(text):
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'&amp;', '&', text)
    text = re.sub(r'&lt;', '<', text)
    text = re.sub(r'&gt;', '>', text)
    text = re.sub(r'&quot;', '"', text)
    text = re.sub(r'&#x27;', "'", text)   # แก้จุดที่ 1
    text = re.sub(r'&#39;', "'", text)
    text = re.sub(r'&#\d+;', '', text)
    text = re.sub(r'&#x[0-9a-fA-F]+;', '', text)
    text = re.sub(r'&\w+;', '', text)
    text = re.sub(r'\[/?[a-zA-Z]+\]', '', text)
    return text

def remove_markdown_links(text):
    text = re.sub(r'\[([^\]]+)\]\(https?://[^\)]+\)', r'\1', text)
    text = re.sub(r'\[([^\]]+)\]\(#[^\)]*\)', r'\1', text)
    text = re.sub(r'!\[[^\]]*\]\([^\)]+\)', '', text)
    text = re.sub(r'\(https?://[^\)]*\)', '', text)
    return text

def remove_markdown_formatting(text):
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'\*{1,3}_?(.*?)_?\*{1,3}', r'\1', text)
    text = re.sub(r'(?<!\w)_([^_]+)_(?!\w)', r'\1', text)
    text = re.sub(r'~~(.*?)~~', r'\1', text)
    return text

def remove_emoji(text):
    emoji_pattern = re.compile(
        "["
        u"\U0001F600-\U0001F64F"
        u"\U0001F300-\U0001F5FF"
        u"\U0001F680-\U0001F6FF"
        u"\U0001F1E0-\U0001F1FF"
        u"\U00002700-\U000027BF"
        u"\U0001F900-\U0001F9FF"
        u"\U00002600-\U000026FF"
        u"\u2600-\u26FF\u2700-\u27BF"
        "]+", flags=re.UNICODE
    )
    return emoji_pattern.sub('', text)

def normalize_whitespace(text):
    text = re.sub(r'\r\n|\r', '\n', text)
    text = re.sub(r'\t', ' ', text)
    text = re.sub(r' {2,}', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()

def truncate(text, max_len=4096):
    if len(text) > max_len:
        return text[:max_len]
    return text

def clean_text(text, source=''):
    text = remove_html(text)

    if 'mitre' in source or 'telegram' in source:
        text = remove_markdown_links(text)

    if 'telegram' in source:
        text = remove_emoji(text)

    text = remove_markdown_formatting(text)

    text = normalize_whitespace(text)
    text = truncate(text, max_len=4096)
    return text

def filter_record(text, source='', min_len=30):
    if not text or len(text.strip()) < min_len:
        return False
    # แก้จุดที่ 3 — ตัด CVE rejected records ทิ้ง
    if 'cve' in source and text.lower().startswith('rejected reason:'):
        return False
    return True

# ---- Dry-Run ----
def dryrun_file(filename, sample_size=500):
    path = f"{RAW}/{filename}"
    if not os.path.exists(path):
        return

    source = filename.replace('.jsonl', '')
    log.info(f"[DRY-RUN] {filename} (sample {sample_size} records)")

    records = []
    with open(path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if i >= sample_size:
                break
            try:
                records.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                pass

    total      = len(records)
    dropped    = 0
    truncated  = 0
    cleaned    = 0

    before_after = []

    for record in records:
        text = record.get('text', '') or ''
        original_len = len(text)

        text_cleaned = clean_text(text, source=source)

        if not filter_record(text_cleaned, source=source):
            dropped += 1
            continue

        if len(text_cleaned) < original_len:
            if original_len > 4096:
                truncated += 1
            else:
                cleaned += 1

        # เก็บตัวอย่าง before/after 3 อัน
        if len(before_after) < 3 and text != text_cleaned:
            before_after.append((text[:150], text_cleaned[:150]))

    log.info(f"  Sample total   : {total}")
    log.info(f"  Dropped        : {dropped} (too short)")
    log.info(f"  Truncated      : {truncated} (>4096 chars)")
    log.info(f"  Cleaned        : {cleaned} (html/emoji removed)")
    log.info(f"  Pass           : {total - dropped}")

    if before_after:
        log.info(f"  --- BEFORE/AFTER samples ---")
        for i, (b, a) in enumerate(before_after):
            log.info(f"  [{i+1}] BEFORE: {repr(b)}")
            log.info(f"  [{i+1}] AFTER : {repr(a)}")

    log.info("")

if __name__ == "__main__":
    log.info("="*60)
    log.info("DRY-RUN CLEANING REPORT")
    log.info("="*60)

    files = sorted([
        f for f in os.listdir(RAW) if f.endswith('.jsonl')
    ])

    for filename in files:
        dryrun_file(filename, sample_size=500)

    log.info("="*60)
    log.info("Dry-run เสร็จแล้ว ตรวจสอบ before/after แล้วค่อยรัน cleaning จริง")
    log.info("="*60)
