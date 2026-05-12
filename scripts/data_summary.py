import os

RAW = os.path.expanduser("~/osint-project/data/raw")

def format_size(b):
    if b < 1024**2:
        return f"{b//1024} KB"
    return f"{b//1024//1024} MB"

def main():
    print(f"\n{'ไฟล์':<35} {'Records':>8}  {'ขนาด':>8}")
    print("-"*55)
    total_records = 0
    total_bytes   = 0
    for filename in sorted(os.listdir(RAW)):
        if not filename.endswith('.jsonl'):
            continue
        path = f"{RAW}/{filename}"
        lines = sum(1 for _ in open(path, 'r', encoding='utf-8'))
        size  = os.path.getsize(path)
        print(f"  {filename:<33} {lines:>8,}  {format_size(size):>8}")
        total_records += lines
        total_bytes   += size
    print("-"*55)
    print(f"  {'รวมทั้งหมด':<33} {total_records:>8,}  {format_size(total_bytes):>8}")

if __name__ == "__main__":
    main()
