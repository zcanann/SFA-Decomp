#!/usr/bin/env python3
"""Bulk-fetch decomp.me scratches referenced by the Discord export.

Pulls scratch metadata + source + target asm into JSONL for later searching.
Uses playwright to bypass Cloudflare's bot challenge.

Usage:
    python3 tools/decompme_fetch.py               # fetch all referenced scratches
    python3 tools/decompme_fetch.py --limit 10    # smoke-test on 10
    python3 tools/decompme_fetch.py --resume      # skip slugs already in the JSONL
    python3 tools/decompme_fetch.py --delay 3     # seconds between requests

Output: reference_projects/decompme_scratches.jsonl
Each line is a JSON object with these fields:
    slug, name, compiler, platform, source_code, context, score, max_score,
    creation_time, last_updated, owner, language, compiler_flags,
    asm_target  (joined "addr: instr" lines from the target binary)
    asm_current (joined "addr: instr" lines from the user's compiled C)
    diff_label, http_status (200 / 404 / ERR)
"""
import argparse
import csv
import glob
import json
import re
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parent.parent
CSV_GLOB = str(REPO / "reference_projects" / "Discord_chat*.csv")
OUT_PATH = REPO / "reference_projects" / "decompme_scratches.jsonl"

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
SCRATCH_RE = re.compile(r"decomp\.me/scratch/([A-Za-z0-9]+)")


def slugs_from_csv():
    paths = sorted(glob.glob(CSV_GLOB))
    if not paths:
        sys.exit(f"No Discord CSV under {CSV_GLOB}")
    seen = []
    with open(paths[0], newline="", encoding="utf-8-sig") as f:
        r = csv.reader(f)
        next(r)
        for row in r:
            if len(row) < 4:
                continue
            for m in SCRATCH_RE.finditer(row[3]):
                slug = m.group(1)
                if slug not in seen:
                    seen.append(slug)
    return seen


def already_fetched():
    if not OUT_PATH.exists():
        return set()
    out = set()
    with open(OUT_PATH) as f:
        for line in f:
            try:
                out.add(json.loads(line)["slug"])
            except Exception:
                pass
    return out


def flatten_text_chunks(chunks):
    """Convert diff_output row text-chunks back to a flat string."""
    if not chunks:
        return ""
    parts = []
    for chunk in chunks.get("text", []):
        parts.append(chunk.get("text", ""))
    return "".join(parts).strip()


def render_asm(diff_output, side):
    """Return one-line-per-row 'addr: instr' for either 'base' or 'current'."""
    rows = diff_output.get("rows", []) if diff_output else []
    out = []
    for row in rows:
        side_data = row.get(side)
        if not side_data:
            out.append("")
            continue
        flat = flatten_text_chunks(side_data)
        if flat:
            out.append(flat)
    return "\n".join(out)


def fetch_one(page, slug, delay):
    """Returns dict with all scratch fields + asm. http_status indicates outcome."""
    try:
        meta = page.evaluate(f"""async () => {{
            const r = await fetch('/api/scratch/{slug}', {{headers: {{'Accept': 'application/json'}}}});
            return {{status: r.status, body: await r.text()}};
        }}""")
    except Exception as e:
        return {"slug": slug, "http_status": "ERR", "error": str(e)[:200]}
    if meta["status"] != 200:
        return {"slug": slug, "http_status": meta["status"]}
    try:
        d = json.loads(meta["body"])
    except Exception:
        return {"slug": slug, "http_status": "JSON_ERR"}
    time.sleep(delay)
    try:
        comp = page.evaluate(f"""async () => {{
            const r = await fetch('/api/scratch/{slug}/compile', {{headers: {{'Accept': 'application/json'}}}});
            return {{status: r.status, body: await r.text()}};
        }}""")
    except Exception as e:
        comp = {"status": "ERR", "body": ""}
    asm_target = asm_current = ""
    score = d.get("score")
    if comp.get("status") == 200:
        try:
            cd = json.loads(comp["body"])
            diff = cd.get("diff_output", {})
            asm_target = render_asm(diff, "base")
            asm_current = render_asm(diff, "current")
            score = diff.get("current_score", score)
        except Exception:
            pass
    return {
        "slug": slug,
        "http_status": 200,
        "name": d.get("name", ""),
        "compiler": d.get("compiler", ""),
        "platform": d.get("platform", ""),
        "language": d.get("language", ""),
        "compiler_flags": d.get("compiler_flags", ""),
        "diff_label": d.get("diff_label", ""),
        "owner": (d.get("owner") or {}).get("username", ""),
        "creation_time": d.get("creation_time", ""),
        "last_updated": d.get("last_updated", ""),
        "score": score,
        "max_score": d.get("max_score"),
        "source_code": d.get("source_code", ""),
        "context": d.get("context", ""),
        "asm_target": asm_target,
        "asm_current": asm_current,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--limit", "-n", type=int, default=0, help="stop after N (0=all)")
    p.add_argument("--resume", action="store_true", help="skip slugs already in JSONL")
    p.add_argument("--delay", type=float, default=2.0, help="seconds between requests (default 2.0)")
    p.add_argument("--cf-wait", type=float, default=10.0, help="seconds to wait after first page-load for CF challenge")
    args = p.parse_args()

    slugs = slugs_from_csv()
    print(f"=== {len(slugs)} unique scratches referenced in Discord export ===")
    skip = already_fetched() if args.resume else set()
    if skip:
        print(f"=== {len(skip)} already in {OUT_PATH.name}; skipping ===")
    todo = [s for s in slugs if s not in skip]
    if args.limit:
        todo = todo[: args.limit]
    print(f"=== fetching {len(todo)} scratch(es) with {args.delay}s delay ===")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(user_agent=UA)
        page = ctx.new_page()
        print(f"=== loading decomp.me to acquire CF cookies (waiting {args.cf_wait}s) ===")
        page.goto("https://decomp.me/", wait_until="domcontentloaded", timeout=45000)
        time.sleep(args.cf_wait)
        # Probe to confirm cookies cleared
        probe = page.evaluate("""async () => (await fetch('/api/scratch/__nonexistent__/probe')).status""")
        if probe == 404:
            print("=== CF cookies acquired (probe got 404 not 403) — proceeding ===")
        else:
            print(f"=== probe returned HTTP {probe} — proceeding anyway ===")

        with open(OUT_PATH, "a") as out:
            for i, slug in enumerate(todo, 1):
                row = fetch_one(page, slug, args.delay)
                out.write(json.dumps(row) + "\n")
                out.flush()
                if i % 20 == 0 or i == len(todo):
                    print(f"  [{i}/{len(todo)}] {slug} http={row.get('http_status')} "
                          f"name={row.get('name', '')[:40]}")
                time.sleep(args.delay)
        browser.close()
    print(f"=== wrote {OUT_PATH} ===")


if __name__ == "__main__":
    main()
