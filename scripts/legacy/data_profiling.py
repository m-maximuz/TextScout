import json, os, logging
from pathlib import Path

RAW     = os.path.expanduser("~/osint-project/data/01_raw")
LOG_DIR = os.path.expanduser("~/osint-project/logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/profiling.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

def profile_file(filepath):
    filename = Path(filepath).name
    log.info(f"Profiling {filename}...")

    total       = 0
    empty       = 0
    broken_json = 0
    lengths     = []

    with open(filepath, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                text   = record.get('text', '') or ''
                total += 1
                if not text or len(text.strip()) == 0:
                    empty += 1
                else:
                    lengths.append(len(text))
            except json.JSONDecodeError:
                broken_json += 1

    if not lengths:
        log.warning(f"  {filename}: ไม่มีข้อมูลเลย")
        return

    log.info(f"  Total records  : {total:,}")
    log.info(f"  Empty text     : {empty:,}")
    log.info(f"  Broken JSON    : {broken_json:,}")
    log.info(f"  Length min     : {min(lengths):,} chars")
    log.info(f"  Length max     : {max(lengths):,} chars")
    log.info(f"  Length avg     : {int(sum(lengths)/len(lengths)):,} chars")
    log.info(f"  Length median  : {sorted(lengths)[len(lengths)//2]:,} chars")

    # แจ้งเตือนถ้ามีข้อความยาวเกิน 4096 (context window ปกติ)
    too_long = sum(1 for l in lengths if l > 4096)
    if too_long > 0:
        log.warning(f"  ⚠️  ยาวเกิน 4096 chars: {too_long:,} records — ต้อง truncate")

    print()

if __name__ == "__main__":
    log.info("="*60)
    log.info("DATA PROFILING REPORT")
    log.info("="*60)

    files = sorted([
        f for f in os.listdir(RAW) if f.endswith('.jsonl')
    ])

    for filename in files:
        profile_file(f"{RAW}/{filename}")

    log.info("="*60)
    log.info("Profiling เสร็จแล้ว ดู logs/profiling.log สำหรับรายละเอียด")
    log.info("="*60)
