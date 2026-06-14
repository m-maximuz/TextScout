import json, os, time, hashlib
from telethon.sync import TelegramClient
from telethon.errors import FloodWaitError, ChannelPrivateError

API_ID   = os.environ.get("TELEGRAM_API_ID")
API_HASH = os.environ.get("TELEGRAM_API_HASH")
RAW      = os.path.expanduser("~/osint-project/data/raw")

CHANNELS = [
    "cveNotify",
    "TheDarkWebInformer",
    "secharvest",
    "cybersecuritynews",
    "malwrhunterteam",
    "vxunderground",
]

def make_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_existing(filepath):
    seen = set()
    if not os.path.exists(filepath):
        return seen
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                r = json.loads(line.strip())
                seen.add(make_hash(r['text']))
            except (json.JSONDecodeError, KeyError):
                pass
    return seen

def save(filepath, entry, seen):
    h = make_hash(entry['text'])
    if h in seen:
        return 0
    seen.add(h)
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    return 1

def count_records(filepath):
    if not os.path.exists(filepath):
        return 0
    with open(filepath, 'r', encoding='utf-8') as f:
        return sum(1 for _ in f)

def collect():
    path = f"{RAW}/telegram.jsonl"
    seen = load_existing(path)
    total = 0

    with TelegramClient('osint_session', API_ID, API_HASH) as client:
        for channel in CHANNELS:
            count = 0
            print(f"\n[*] @{channel}...")
            try:
                for msg in client.iter_messages(channel, limit=2000):
                    if not msg.text:
                        continue
                    text = msg.text.strip()
                    if len(text) < 20:
                        continue
                    count += save(path, {
                        "text":    text,
                        "source":  f"telegram_{channel}",
                        "channel": channel,
                        "date":    str(msg.date)
                    }, seen)
                print(f"  [+] @{channel}: เพิ่ม {count} records ใหม่")
                total += count
                time.sleep(3)
            except ChannelPrivateError:
                print(f"  [!] @{channel}: channel เป็น private ข้ามไป")
            except FloodWaitError as e:
                print(f"  [!] Flood wait {e.seconds} วิ...")
                time.sleep(e.seconds)
            except Exception as e:
                print(f"  [!] @{channel}: {e}")

    print(f"\n{'='*50}")
    print(f"  รวม telegram.jsonl: {count_records(path):,} records")
    print(f"  เพิ่มใหม่รอบนี้: {total:,} records")
    print(f"{'='*50}")

if __name__ == "__main__":
    os.makedirs(RAW, exist_ok=True)
    collect()
