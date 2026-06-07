#!/usr/bin/env python3
"""rotation_decl_audit.py -- project-wide recipe-#115 candidate detector.

Recipe #115 (landing dcfea98ab): CALLEE-DECL PARAM WIDTHS shift the caller's
web CREATION ORDER at zero instruction cost. A narrowing-cast call argument
(`f(0, (u16)(v < 500 ? 500 : v), h, 1)`) against a Ghidra-flattened all-int
extern leaves a persistent no-op conversion node that scrambles the #108
within-class saved-reg ranks -- byte-identical instructions, wrong registers.
Music_Update 97.78->98.70 from one #57 block-scope decl proved the lever.

This tool scans every <100% function for the #115 SIGNATURE:
  1. REGISTER ROTATION: target/current instruction streams have equal length
     and are (near-)identical after masking register numbers -- the divergence
     is coloring, not code.
  2. CALLS IN BODY: at least one `bl` (call-free leaves are out of #115's
     reach BY MECHANISM -- see the #115 scope notes; the conversion nodes
     live on call arguments).
  3. NARROWING CASTS in the caller's source body ((u8)/(u16)/(s8)/(s16)
     and friends) -- the raw material for the conversion nodes.
  4. DECL FLATNESS: the fn's callees' visible extern decls are predominantly
     int/u32/undefined4 (the Ghidra-flattening marker). Decl-vs-def width
     DISAGREEMENT is reported when detectable (strong candidates: the def or
     an existing #57 block extern names the true narrow signature, as
     synth_handle.c did for sndSeqVolume).

Ranking: unmatched_bytes (size * (100-fuzzy)/100) * rotation_frac, gated on
calls>0 and casts>0, scaled by mean callee flatness. High score = big payoff,
high confidence.

Usage:
  python3 tools/rotation_decl_audit.py [--min-fuzzy 90] [--max-fuzzy 99.99]
      [--min-size 96] [--max-size 8192] [--top 60] [--unit-filter SUBSTR]

Output: one line per candidate, plus per-fn callee decl detail for the top
entries. Treat it as a triage queue, not a verdict: run the #115 standalone-TU
diagnostic (extract fn + minimal decls; if the probe matches TARGET coloring,
bisect decls) before editing. Verified hit on first run: Music_Update's
already-fixed siblings rank where expected; see task #12 metadata for the
inaugural run's filing.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VERSION = "GSAE01"

FLAT_TYPES = {"int", "s32", "u32", "uint", "long", "undefined4", "undefined", "size_t"}
NARROW_TYPES = {"u8", "s8", "u16", "s16", "char", "short", "uchar", "ushort", "byte", "bool", "undefined2", "undefined1"}
FP_TYPES = {"f32", "f64", "float", "double"}
CAST_RE = re.compile(r"\(\s*(?:u8|s8|u16|s16|uchar|ushort|char|short)\s*\)")
REG_RE = re.compile(r"\b([rf])\d+\b|\bcr\d\b")
INSTR_RE = re.compile(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
RELOC_RE = re.compile(r"R_PPC_REL24\s+(\S+)")


def objdump(objdump_path: Path, obj: Path) -> str:
    return subprocess.run([str(objdump_path), "-dr", str(obj)],
                          check=True, capture_output=True, text=True).stdout


def split_functions(disasm: str) -> dict[str, list[str]]:
    fns: dict[str, list[str]] = {}
    cur = None
    for line in disasm.splitlines():
        m = re.match(r"^[0-9a-f]+ <(.+)>:$", line)
        if m:
            cur = m.group(1)
            fns[cur] = []
            continue
        if cur is not None:
            fns[cur].append(line)
    return fns


def parse_stream(lines: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Return ((mnemonic, operands) list, callee reloc names)."""
    stream: list[tuple[str, str]] = []
    callees: list[str] = []
    for ln in lines:
        m = INSTR_RE.match(ln)
        if m:
            ops = re.sub(r"\b[0-9a-f]{2,8}\b(?= <|$)", "ADDR", m.group(2))
            stream.append((m.group(1), ops))
            continue
        r = RELOC_RE.search(ln)
        if r and not r.group(1).startswith(("_savegpr", "_restgpr", "_savefpr", "_restfpr")):
            callees.append(r.group(1))
    return stream, callees


def mask_regs(stream: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(mn, REG_RE.sub(lambda m: (m.group(1) or "c") + "X", ops)) for mn, ops in stream]


def rotation_frac(t: list[tuple[str, str]], c: list[tuple[str, str]]) -> float:
    """1.0 = identical after reg masking (pure rotation). 0 = structural."""
    if not t or len(t) != len(c):
        return 0.0
    mt, mc = mask_regs(t), mask_regs(c)
    same_masked = sum(1 for a, b in zip(mt, mc) if a == b)
    raw_diff = sum(1 for a, b in zip(t, c) if a != b)
    if raw_diff == 0:
        return 0.0  # already byte-equal modulo addrs; not a rotation problem
    return same_masked / len(t)


DECL_CACHE: dict[str, list[str]] = {}


def build_decl_index() -> None:
    """Scan src/ + include/ once for `name(params)` decl lines."""
    pat = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{)(]*(?:\([^)]*\))?[^;{)(]*)\)\s*;")
    for root in (REPO / "src", REPO / "include"):
        for p in root.rglob("*"):
            if p.suffix not in (".c", ".h"):
                continue
            try:
                text = p.read_bytes().decode("latin-1")
            except OSError:
                continue
            for m in pat.finditer(text):
                DECL_CACHE.setdefault(m.group(1), []).append(m.group(2))


def flatness(callee: str) -> tuple[float, bool]:
    """(mean flat-param fraction over decls, decls-disagree?)"""
    decls = DECL_CACHE.get(callee)
    if not decls:
        return 0.0, False
    fracs = []
    for params in decls[:8]:
        parts = [x.strip() for x in params.split(",") if x.strip() and x.strip() != "void"]
        if not parts:
            continue
        flat = 0
        total = 0
        for part in parts:
            words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", part)
            if not words:
                continue
            total += 1
            tw = set(words)
            if tw & NARROW_TYPES or tw & FP_TYPES or "*" in part:
                continue
            if tw & FLAT_TYPES:
                flat += 1
        if total:
            fracs.append(flat / total)
    if not fracs:
        return 0.0, False
    return sum(fracs) / len(fracs), (max(fracs) - min(fracs)) > 0.34


def count_caller_casts(source_path: Path, fn: str) -> int:
    try:
        text = source_path.read_bytes().decode("latin-1")
    except OSError:
        return 0
    m = re.search(r"^[A-Za-z_][^\n;]*\b" + re.escape(fn) + r"\s*\(", text, re.M)
    if not m:
        return 0
    i = text.find("{", m.start())
    if i < 0:
        return 0
    depth = 0
    j = i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return len(CAST_RE.findall(text[i:j]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-fuzzy", type=float, default=90.0)
    ap.add_argument("--max-fuzzy", type=float, default=99.99)
    ap.add_argument("--min-size", type=int, default=96)
    ap.add_argument("--max-size", type=int, default=8192)
    ap.add_argument("--top", type=int, default=60)
    ap.add_argument("--unit-filter", default="")
    args = ap.parse_args()

    objdump_path = REPO / "build" / "binutils" / "powerpc-eabi-objdump"
    config = json.loads((REPO / "build" / VERSION / "config.json").read_text())
    report = json.loads((REPO / "build" / VERSION / "report.json").read_text())
    obj_by_name = {u["name"]: u["object"] for u in config["units"]}

    build_decl_index()

    rows = []
    for unit in report["units"]:
        meta = unit.get("metadata") or {}
        src = meta.get("source_path")
        if not src:
            continue
        if args.unit_filter and args.unit_filter not in unit["name"]:
            continue
        cands = []
        for fn in unit.get("functions", []):
            if "fuzzy_match_percent" not in fn or "size" not in fn:
                continue
            fz = float(fn["fuzzy_match_percent"])
            sz = int(fn["size"])
            if not (args.min_fuzzy <= fz < args.max_fuzzy):
                continue
            if not (args.min_size <= sz <= args.max_size):
                continue
            cands.append(fn)
        if not cands:
            continue
        cfg_name = src.replace("src/", "", 1)
        obj = obj_by_name.get(cfg_name)
        if not obj:
            continue
        tgt_o = REPO / obj
        cur_o = REPO / obj.replace(f"build/{VERSION}/obj/", f"build/{VERSION}/src/")
        if not (tgt_o.is_file() and cur_o.is_file()):
            continue
        tfns = split_functions(objdump(objdump_path, tgt_o))
        cfns = split_functions(objdump(objdump_path, cur_o))
        for fn in cands:
            name = fn["name"]
            if name not in tfns or name not in cfns:
                continue
            t_stream, t_callees = parse_stream(tfns[name])
            c_stream, _ = parse_stream(cfns[name])
            rot = rotation_frac(t_stream, c_stream)
            if rot < 0.85:
                continue
            ncalls = len(t_callees)
            if ncalls == 0:
                continue  # #115 scope: call-free leaves are out of reach
            casts = count_caller_casts(REPO / src, name)
            if casts == 0:
                continue
            flats = [flatness(c) for c in set(t_callees)]
            mean_flat = sum(f for f, _ in flats) / len(flats) if flats else 0.0
            disagree = any(d for _, d in flats)
            unmatched = int(fn["size"]) * (100.0 - float(fn["fuzzy_match_percent"])) / 100.0
            score = unmatched * rot * (0.25 + mean_flat) * (1.5 if disagree else 1.0)
            rows.append((score, unmatched, rot, ncalls, casts, mean_flat, disagree,
                         unit["name"], name, fn["fuzzy_match_percent"], fn["size"],
                         sorted(set(t_callees))))

    rows.sort(reverse=True)
    print(f"=== {len(rows)} #115 candidates (rotation>=0.85, calls>0, casts>0) ===")
    print(f"{'score':>7} {'unmB':>6} {'rot':>5} {'bl':>3} {'cast':>4} {'flat':>5} {'dis':>3}  fn")
    for r in rows[: args.top]:
        score, unm, rot, ncalls, casts, mf, dis, uname, fname, fz, sz, callees = r
        print(f"{score:7.1f} {unm:6.1f} {rot:5.2f} {ncalls:3d} {casts:4d} {mf:5.2f} {'Y' if dis else ' ':>3}  "
              f"{fname}  [{uname} {fz}% {sz}B]")
    print()
    for r in rows[: min(args.top, 15)]:
        _, _, _, _, _, _, _, uname, fname, _, _, callees = r
        print(f"--- {fname} callees: {', '.join(callees[:10])}")


if __name__ == "__main__":
    main()
