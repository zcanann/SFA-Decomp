#!/usr/bin/env python3
"""Search the matching-help corpus: Discord export + fetched decomp.me scratches.

Usage:
    python3 tools/discord_search.py <keyword>...
    python3 tools/discord_search.py "rlwinm" "switch"
    python3 tools/discord_search.py --context 5 "fp_contract"
    python3 tools/discord_search.py --scratches "f27 register"
    python3 tools/discord_search.py --asm "rsqrte" "fmadds"     # search inside target asm
    python3 tools/discord_search.py --code "register u32"        # search inside C source

Discord search returns hits with N messages before/after for thread context.
Scratch search returns scratch metadata + source preview + asm preview.

Searches the static scratch-corpus snapshot (reference_projects/decompme_scratches.jsonl).
"""
import argparse
import csv
import glob
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CSV_GLOB = str(REPO / "reference_projects" / "Discord_chat*.csv")
SCRATCH_JSONL = REPO / "reference_projects" / "decompme_scratches.jsonl"


def load_discord():
    paths = sorted(glob.glob(CSV_GLOB))
    if not paths:
        return []
    rows = []
    with open(paths[0], newline="", encoding="utf-8-sig") as f:
        r = csv.reader(f)
        next(r)
        for row in r:
            if len(row) < 4:
                continue
            rows.append((row[0], row[1], row[3]))
    return rows


def load_scratches():
    if not SCRATCH_JSONL.exists():
        return []
    out = []
    with open(SCRATCH_JSONL) as f:
        for line in f:
            try:
                d = json.loads(line)
                if d.get("http_status") == 200:
                    out.append(d)
            except Exception:
                pass
    return out


def search_discord(rows, needles, scratches_only, context, cap):
    hits = []
    for i, (ts, user, content) in enumerate(rows):
        c_low = content.lower()
        if not all(n in c_low for n in needles):
            continue
        if scratches_only and "decomp.me/scratch" not in content:
            continue
        hits.append(i)
    print(f"=== DISCORD: {len(hits)} hit(s) for {needles} "
          f"({'scratches only' if scratches_only else 'all messages'}) ===\n")
    for h in hits[:cap]:
        lo = max(0, h - context)
        hi = min(len(rows), h + context + 1)
        for j in range(lo, hi):
            ts, user, c = rows[j]
            marker = ">>>" if j == h else "   "
            print(f"{marker} [{ts}] {user}: {c[:500]}{'...' if len(c) > 500 else ''}")
        scratches = re.findall(r"decomp\.me/scratch/([A-Za-z0-9]+)", rows[h][2])
        if scratches:
            print(f"    scratches: {', '.join(set(scratches))}")
        print("-" * 70)
    if len(hits) > cap:
        print(f"... {len(hits) - cap} more hidden (raise --max)\n")


def preview(text, width, lines):
    if not text:
        return "<empty>"
    snip = text[:width * lines]
    return "\n      ".join(snip.splitlines()[:lines])


def search_scratches(scratches, needles, field, cap):
    """Search inside scratch source code, asm, or all-text."""
    field_map = {
        "code": ["source_code", "context"],
        "asm": ["asm_target", "asm_current"],
        "all": ["source_code", "context", "asm_target", "asm_current", "name", "diff_label"],
    }
    fields = field_map.get(field, field_map["all"])
    hits = []
    for d in scratches:
        blob = "\n".join(str(d.get(f, "")) for f in fields).lower()
        if all(n in blob for n in needles):
            hits.append(d)
    print(f"=== SCRATCHES: {len(hits)} hit(s) for {needles} (field={field}) ===\n")
    for d in hits[:cap]:
        name = d.get("name", "?")
        slug = d.get("slug", "?")
        score = d.get("score", "?")
        ms = d.get("max_score", "?")
        plat = d.get("platform", "?")
        comp = d.get("compiler", "?")
        owner = d.get("owner", "?")
        print(f"  {name}  [{slug}]  score={score}/{ms}  {plat}/{comp}  by {owner}")
        print(f"  https://decomp.me/scratch/{slug}")
        if field in ("code", "all"):
            src = d.get("source_code", "")
            if src:
                print(f"    source_code ({len(src)}B preview):")
                print(f"      {preview(src, 100, 8)}")
        if field in ("asm", "all"):
            for asm_field in ("asm_target", "asm_current"):
                a = d.get(asm_field, "")
                if a:
                    # find the lines matching any keyword for asm-grep
                    matched = [ln for ln in a.splitlines() if any(n in ln.lower() for n in needles)]
                    if matched:
                        print(f"    {asm_field} matching lines ({len(matched)} of {a.count(chr(10))}):")
                        for ln in matched[:6]:
                            print(f"      {ln}")
        print("-" * 70)
    if len(hits) > cap:
        print(f"... {len(hits) - cap} more hidden (raise --max)\n")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("keywords", nargs="+", help="terms (case-insensitive); ALL must appear")
    p.add_argument("--context", "-C", type=int, default=2, help="Discord context (default 2)")
    p.add_argument("--scratches", action="store_true",
                   help="only Discord messages with scratch links")
    p.add_argument("--max", "-n", type=int, default=20, help="cap hits (default 20)")
    p.add_argument("--asm", action="store_true",
                   help="search inside scratch asm only (target + current)")
    p.add_argument("--code", action="store_true",
                   help="search inside scratch C source only")
    p.add_argument("--skip-discord", action="store_true", help="skip Discord search")
    p.add_argument("--skip-scratches", action="store_true", help="skip scratch search")
    args = p.parse_args()

    needles = [k.lower() for k in args.keywords]

    if not args.skip_discord:
        rows = load_discord()
        if not rows:
            print(f"WARN: no Discord CSV found under {CSV_GLOB}", file=sys.stderr)
        else:
            search_discord(rows, needles, args.scratches, args.context, args.max)

    if not args.skip_scratches:
        scratches = load_scratches()
        if not scratches:
            print(f"WARN: no scratch corpus at {SCRATCH_JSONL} (static snapshot, not regenerable)", file=sys.stderr)
        else:
            field = "asm" if args.asm else "code" if args.code else "all"
            search_scratches(scratches, needles, field, args.max)


if __name__ == "__main__":
    main()
