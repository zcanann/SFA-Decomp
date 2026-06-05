#!/usr/bin/env python3
"""Search the decomp.me Discord export for matching-related discussions.

Usage:
    python3 tools/discord_search.py <keyword>...
    python3 tools/discord_search.py "rlwinm" "register"
    python3 tools/discord_search.py --context 5 "fp_contract"
    python3 tools/discord_search.py --scratches "f27 register"

Each hit shows the matching message plus N messages before/after for thread context
(Discord messages aren't threaded, so timestamps + adjacency are the only signal).
"""
import argparse
import csv
import glob
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CSV_GLOB = str(REPO / "reference_projects" / "Discord_chat*.csv")


def load(csv_path):
    rows = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        r = csv.reader(f)
        next(r)
        for row in r:
            if len(row) < 4:
                continue
            ts, user, _tag, content = row[0], row[1], row[2], row[3]
            rows.append((ts, user, content))
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("keywords", nargs="+", help="terms (case-insensitive); ALL must appear")
    p.add_argument("--context", "-C", type=int, default=2,
                   help="messages before/after each hit (default 2)")
    p.add_argument("--scratches", action="store_true",
                   help="only show hits that contain a decomp.me/scratch link")
    p.add_argument("--max", "-n", type=int, default=20,
                   help="cap displayed hits (default 20)")
    args = p.parse_args()

    paths = sorted(glob.glob(CSV_GLOB))
    if not paths:
        print(f"No Discord CSV under {CSV_GLOB}", file=sys.stderr)
        sys.exit(1)
    rows = load(paths[0])
    needles = [k.lower() for k in args.keywords]

    hits = []
    for i, (ts, user, content) in enumerate(rows):
        c_low = content.lower()
        if not all(n in c_low for n in needles):
            continue
        if args.scratches and "decomp.me/scratch" not in content:
            continue
        hits.append(i)

    print(f"=== {len(hits)} hit(s) for {args.keywords} "
          f"({'scratches only' if args.scratches else 'all messages'}) ===\n")
    for h in hits[: args.max]:
        lo = max(0, h - args.context)
        hi = min(len(rows), h + args.context + 1)
        for j in range(lo, hi):
            ts, user, c = rows[j]
            marker = ">>>" if j == h else "   "
            print(f"{marker} [{ts}] {user}: {c[:500]}{'...' if len(c) > 500 else ''}")
        # extract scratch links from the hit
        scratches = re.findall(r"decomp\.me/scratch/[A-Za-z0-9]+", rows[h][2])
        if scratches:
            print(f"    scratches: {', '.join(set(scratches))}")
        print("-" * 70)
    if len(hits) > args.max:
        print(f"... {len(hits) - args.max} more hidden (raise --max)")


if __name__ == "__main__":
    main()
