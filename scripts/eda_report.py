"""Full EDA report across every dataset version.

Writes per-version folders (reports/eda/<version>/) and a cross-version
comparison (reports/eda/versions/). IOC + technique methodology matches eda.py
(defanged-IOC regexes over full record text), so numbers are comparable to the
existing single-version EDA and to PROJECT_SUMMARY.md.

Public version -> file mapping is verified against PROJECT_SUMMARY.md record
counts (114403 / 53469 / 46312 / 41371 / 16399). Internal cleaning labels are
offset by one generation, so they are NOT used on the axes.
"""
import json
import os
import re
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = os.path.expanduser("~/osint-project")
EDA = f"{BASE}/reports/eda"

VERSIONS = [
    ("v1",   [f"{BASE}/data/02_processed/v2_0_cleaned.jsonl"]),
    ("v2.0", [f"{BASE}/data/02_processed/v3_0_cleaned.jsonl"]),
    ("v2.2", [f"{BASE}/data/02_processed/v3_2_cleaned.jsonl"]),
    ("v2.3", [f"{BASE}/data/02_processed/v3_3_cleaned.jsonl"]),
    ("v3",   [f"{BASE}/data/03_splits_v3.4/{s}.jsonl" for s in ("train", "valid", "test")]),
]

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
IP_RE = re.compile(r"\b\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\b")
DOM_RE = re.compile(r"\b[a-zA-Z0-9\-]+\[\.\][a-zA-Z]{2,10}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
URL_RE = re.compile(r"hxxps?://")
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
IOC_COLORS = ["#3498db", "#e67e22", "#9b59b6", "#1abc9c", "#e74c3c", "#95a5a6"]


def collect(paths):
    sources, techs = Counter(), Counter()
    lengths = []
    ioc = {"CVE": 0, "IP": 0, "domain": 0, "hash": 0, "url": 0, "no_ioc": 0}
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                sources[r.get("source", "?")] += 1
                msgs = r.get("messages", [])
                full = " ".join(m.get("content", "") for m in msgs)
                for m in msgs:
                    if m.get("role") == "user":
                        lengths.append(len(m.get("content", "")))
                        break
                hit = False
                for name, rx in (("CVE", CVE_RE), ("IP", IP_RE), ("domain", DOM_RE),
                                 ("hash", HASH_RE), ("url", URL_RE)):
                    if rx.search(full):
                        ioc[name] += 1
                        hit = True
                if not hit:
                    ioc["no_ioc"] += 1
                techs.update(TECH_RE.findall(full))
    n = sum(sources.values())
    return {"n": n, "sources": sources, "lengths": lengths, "ioc": ioc,
            "techs": techs, "syn": sources.get("synthetic_uncertainty", 0)}


def median(xs):
    s = sorted(xs)
    m = len(s) // 2
    return (s[m] if len(s) % 2 else (s[m-1] + s[m]) / 2) if s else 0


def per_version(label, d):
    out = f"{EDA}/by_version/{label}"
    os.makedirs(out, exist_ok=True)
    n = d["n"]

    items = d["sources"].most_common()
    names = [k for k, _ in items][::-1]
    vals = [v for _, v in items][::-1]
    fig, ax = plt.subplots(figsize=(8, max(3, 0.4 * len(names) + 1)))
    ax.barh(names, vals, color="#2c6fbb")
    for i, v in enumerate(vals):
        ax.text(v, i, f" {v:,}", va="center", fontsize=8)
    ax.set_title(f"{label} — source distribution ({n:,} records)")
    ax.margins(x=0.12)
    fig.tight_layout(); fig.savefig(f"{out}/source_distribution.png", dpi=140); plt.close(fig)

    keys = ["CVE", "IP", "domain", "hash", "url", "no_ioc"]
    vals = [d["ioc"][k] for k in keys]
    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.bar(keys, vals, color=IOC_COLORS, edgecolor="black")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width()/2, v, f"{100*v/n:.1f}%", ha="center", va="bottom", fontsize=9)
    ax.set_title(f"{label} — IOC type coverage")
    ax.set_ylabel("records"); ax.margins(y=0.12)
    fig.tight_layout(); fig.savefig(f"{out}/ioc_coverage.png", dpi=140); plt.close(fig)

    clipped = [min(x, 2500) for x in d["lengths"]]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(clipped, bins=40, color="#7a4fbf", edgecolor="white")
    mu, md = sum(d["lengths"])/n, median(d["lengths"])
    ax.axvline(mu, color="#e74c3c", ls="--", label=f"mean {mu:.0f}")
    ax.axvline(md, color="#2e8b57", ls="--", label=f"median {md:.0f}")
    ax.set_title(f"{label} — user-message length (chars, capped 2500)")
    ax.set_xlabel("chars"); ax.set_ylabel("records"); ax.legend()
    fig.tight_layout(); fig.savefig(f"{out}/text_length.png", dpi=140); plt.close(fig)

    top = d["techs"].most_common(15)
    if top:
        names = [k for k, _ in top][::-1]
        vals = [v for _, v in top][::-1]
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.barh(names, vals, color="#16a085")
        ax.set_title(f"{label} — top ATT&CK techniques "
                     f"({len(d['techs'])} unique, {sum(d['techs'].values()):,} mentions)")
        fig.tight_layout(); fig.savefig(f"{out}/top_techniques.png", dpi=140); plt.close(fig)

    with open(f"{out}/summary.md", "w", encoding="utf-8") as f:
        f.write(f"# {label} — EDA summary\n\n")
        f.write(f"- **Records:** {n:,}\n- **Sources:** {len(d['sources'])}\n")
        f.write(f"- **Real / synthetic:** {n-d['syn']:,} / {d['syn']:,} "
                f"({100*d['syn']/n:.1f}% synthetic)\n")
        f.write(f"- **≥1 IOC:** {100*(n-d['ioc']['no_ioc'])/n:.1f}% of records\n")
        f.write(f"- **User-message length:** mean {sum(d['lengths'])/n:.0f}, median {median(d['lengths']):.0f}\n")
        f.write(f"- **Unique ATT&CK techniques:** {len(d['techs'])} "
                f"({sum(d['techs'].values()):,} mentions)\n\n")
        f.write("| Source | Records | % |\n|---|---:|---:|\n")
        for s, c in d["sources"].most_common():
            f.write(f"| {s} | {c:,} | {100*c/n:.1f}% |\n")


def cross_version(stats):
    out = f"{EDA}/overview"
    os.makedirs(out, exist_ok=True)
    labels = [l for l, _ in VERSIONS]

    def bar(values, title, ylabel, fname, color, fmt="{:,}"):
        fig, ax = plt.subplots(figsize=(8, 4.5))
        bars = ax.bar(labels, values, color=color)
        for b, v in zip(bars, values):
            ax.text(b.get_x()+b.get_width()/2, v, fmt.format(v), ha="center", va="bottom", fontsize=9)
        ax.set_title(title); ax.set_ylabel(ylabel); ax.margins(y=0.13)
        fig.tight_layout(); fig.savefig(f"{out}/{fname}", dpi=140); plt.close(fig)

    bar([stats[l]["n"] for l in labels], "Dataset size by version", "records",
        "records_by_version.png", "#2c6fbb")
    bar([len(stats[l]["sources"]) for l in labels], "Number of data sources by version",
        "distinct sources", "sources_by_version.png", "#7a4fbf", "{}")
    bar([round(100*(stats[l]["n"]-stats[l]["ioc"]["no_ioc"])/stats[l]["n"], 1) for l in labels],
        "Signal density: records with ≥1 IOC", "% of records",
        "ioc_coverage_by_version.png", "#16a085", "{}%")
    bar([len(stats[l]["techs"]) for l in labels], "ATT&CK technique coverage by version",
        "unique techniques", "techniques_by_version.png", "#d9822b", "{}")

    total = Counter()
    for l in labels:
        total.update(stats[l]["sources"])
    grounded = ["otx_pulse", "mitre_technique", "mitre_software", "real_cve", "real_actor"]
    maxshare = {s: max(100*stats[l]["sources"].get(s, 0)/stats[l]["n"] for l in labels) for s in total}
    sel = {s for s in total if maxshare[s] >= 3.0} | {s for s in grounded if total.get(s)}
    top = sorted(sel, key=lambda s: total[s], reverse=True)
    palette = list(plt.cm.tab20.colors) + list(plt.cm.tab20b.colors)
    colors = {s: palette[i] for i, s in enumerate(top)}
    colors["other"] = "#cccccc"
    fig, ax = plt.subplots(figsize=(9.5, 5.5))
    bottoms = [0.0]*len(labels)
    for s in top + ["other"]:
        fr = []
        for l in labels:
            src = stats[l]["sources"]
            v = src.get(s, 0) if s != "other" else sum(c for k, c in src.items() if k not in top)
            fr.append(100*v/stats[l]["n"])
        ax.bar(labels, fr, bottom=bottoms, label=s, color=colors[s])
        bottoms = [b+f for b, f in zip(bottoms, fr)]
    ax.set_title("Source composition by version (% of records)")
    ax.set_ylabel("% of records")
    ax.legend(bbox_to_anchor=(1.01, 1), loc="upper left", fontsize=8)
    fig.tight_layout(); fig.savefig(f"{out}/source_composition.png", dpi=140); plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 4.5))
    real = [100*(stats[l]["n"]-stats[l]["syn"])/stats[l]["n"] for l in labels]
    syn = [100*stats[l]["syn"]/stats[l]["n"] for l in labels]
    ax.bar(labels, real, color="#2e8b57", label="real (open-source)")
    ax.bar(labels, syn, bottom=real, color="#d9822b", label="synthetic (honesty signal)")
    for i in range(len(labels)):
        ax.text(i, 100.5, f"{syn[i]:.1f}%", ha="center", fontsize=9)
    ax.set_title("Real vs synthetic by version"); ax.set_ylabel("% of records")
    ax.set_ylim(0, 108); ax.legend(loc="lower left")
    fig.tight_layout(); fig.savefig(f"{out}/real_vs_synthetic.png", dpi=140); plt.close(fig)

    with open(f"{out}/summary.md", "w", encoding="utf-8") as f:
        f.write("| Version | Records | Sources | Synthetic % | ≥1 IOC | Mean user len | Techniques |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|\n")
        for l in labels:
            s = stats[l]
            f.write(f"| {l} | {s['n']:,} | {len(s['sources'])} | {100*s['syn']/s['n']:.1f}% | "
                    f"{100*(s['n']-s['ioc']['no_ioc'])/s['n']:.1f}% | "
                    f"{sum(s['lengths'])/s['n']:.0f} | {len(s['techs'])} |\n")


def main():
    stats = {}
    for label, paths in VERSIONS:
        print(f"[*] {label} ...")
        d = collect(paths)
        stats[label] = d
        per_version(label, d)
    cross_version(stats)
    print(f"[+] EDA report -> {EDA}/ (per-version folders + versions/)")


if __name__ == "__main__":
    main()
