#!/usr/bin/env python3
"""drift_audit.py — detect v1.0/v1.1 source/asm drift across decomp units.

For each unit (or one named unit), this compares the function symbols/sizes in
`src/main/**/*.c` against those in `build/GSAE01/asm/**/*.s` and reports
alignment quality. Drifted units typically have Ghidra-imported function
definitions whose addresses or sizes don't match the v1.0 .s and need the
"add-new-function" or "restructure" pattern (see CLAUDE.md / AGENTS.md) before
per-function byte-matching is tractable.

Usage:
  python3 tools/drift_audit.py                       # rank ALL units
  python3 tools/drift_audit.py main/dll/cannon       # single unit detail
  python3 tools/drift_audit.py --csv > drift.csv     # csv for spreadsheet
  python3 tools/drift_audit.py --min-stubs 5         # filter
  python3 tools/drift_audit.py --only-drifted        # hide aligned units
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BUILD = REPO / "build" / "GSAE01"
SRC = REPO / "src"

# .fn NAME, global  /  .fn NAME, local
ASM_FN_RE = re.compile(r"^\.fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(global|local)\s*$")
# # .text:0xOFF | 0xADDR | size: 0xSIZE
ASM_HDR_RE = re.compile(r"^#\s*\.text:0x[0-9A-Fa-f]+\s*\|\s*0x([0-9A-Fa-f]+)\s*\|\s*size:\s*0x([0-9A-Fa-f]+)")

# In a Ghidra-imported .c, function bodies are usually preceded by an INFO block
# containing the EN v1.0 address and size. We use those when present.
C_INFO_ADDR_RE = re.compile(r"EN\s*v1\.0\s*Address:\s*0x([0-9A-Fa-f]+)", re.IGNORECASE)
C_INFO_SIZE_RE = re.compile(r"EN\s*v1\.0\s*Size:\s*([0-9]+)\s*b", re.IGNORECASE)
C_INFO_FUNC_RE = re.compile(r"Function:\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
# Fallback: a function definition line like `void FUN_8013ffbc(int x) {`
C_DEF_RE = re.compile(
    r"^[A-Za-z_][\w*\s]*?\b(FUN_[0-9A-Fa-f]+|fn_[0-9A-Fa-f]+|[A-Za-z_]\w*)\s*\([^;{]*?\)\s*(?:\{|$)"
)
STUB_NAME_RE = re.compile(r"^(?:FUN_[0-9A-Fa-f]+|fn_[0-9A-Fa-f]+)$")


def parse_asm(path: Path) -> list[dict]:
    """Return list of {name, addr, size} for asm functions in a .s file."""
    funcs: list[dict] = []
    pending_addr = pending_size = None
    if not path.is_file():
        return funcs
    for line in path.read_text(errors="replace").splitlines():
        m = ASM_HDR_RE.match(line)
        if m:
            pending_addr = int(m.group(1), 16)
            pending_size = int(m.group(2), 16)
            continue
        m = ASM_FN_RE.match(line)
        if m:
            funcs.append({
                "name": m.group(1),
                "addr": pending_addr,
                "size": pending_size,
                "linkage": m.group(2),
            })
            pending_addr = pending_size = None
    return funcs


def parse_c(path: Path) -> list[dict]:
    """Return list of {name, addr, size} for functions defined in a .c file.

    Uses Ghidra INFO blocks when present; otherwise records a function with
    name only (addr/size unknown).
    """
    if not path.is_file():
        return []
    text = path.read_text(errors="replace")
    funcs: list[dict] = []
    # Pass 1: find INFO blocks; remember (name, addr, size).
    info_by_name: dict[str, dict] = {}
    info_blocks = re.findall(r"/\*\s*\n(?:\s*\*.*\n)+\s*\*/", text)
    for block in info_blocks:
        nm = C_INFO_FUNC_RE.search(block)
        ad = C_INFO_ADDR_RE.search(block)
        sz = C_INFO_SIZE_RE.search(block)
        if nm:
            info_by_name[nm.group(1)] = {
                "addr": int(ad.group(1), 16) if ad else None,
                "size": int(sz.group(1)) if sz else None,
            }
    # Pass 2: walk lines and pick up definitions at column 0.
    seen = set()
    brace_depth = 0
    in_decl = False
    for line in text.splitlines():
        stripped = line.rstrip()
        # Skip pure comments/blank
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if brace_depth == 0 and (line and line[0] not in " \t"):
            m = C_DEF_RE.match(line)
            if m:
                name = m.group(1)
                # Heuristic: skip obvious typedef/extern/control keywords.
                if name in {"if", "for", "while", "switch", "return", "static"}:
                    continue
                if line.lstrip().startswith(("extern ", "static extern ")):
                    continue
                # Skip pure declarations without a body (no '{' on line and ends in ';')
                # The C_DEF_RE requires '{' at end of line, but a multi-line signature
                # may not include '{' yet.
                if name in seen:
                    continue
                seen.add(name)
                info = info_by_name.get(name, {})
                funcs.append({"name": name, "addr": info.get("addr"), "size": info.get("size")})
        brace_depth += line.count("{") - line.count("}")
        if brace_depth < 0:
            brace_depth = 0
    return funcs


def classify(c_funcs: list[dict], s_funcs: list[dict]) -> dict:
    s_names = {f["name"] for f in s_funcs}
    c_names = {f["name"] for f in c_funcs}
    s_by_addr = {f["addr"]: f for f in s_funcs if f["addr"] is not None}

    matched_by_name = c_names & s_names
    asm_missing_in_src = s_names - c_names
    src_orphan_in_asm = c_names - s_names

    # Among src orphans, classify as v1.0-drifted-Ghidra-import vs real-unused
    drift_evidence = []
    real_orphans = []
    for f in c_funcs:
        if f["name"] in s_names:
            continue
        if f["addr"] is None:
            real_orphans.append(f["name"])
            continue
        # If c.addr matches an asm addr but names differ → renamed; not drift
        if f["addr"] in s_by_addr and s_by_addr[f["addr"]]["name"] != f["name"]:
            drift_evidence.append({"src": f["name"], "addr": f["addr"], "asm": s_by_addr[f["addr"]]["name"]})
        elif STUB_NAME_RE.match(f["name"]):
            # FUN_/fn_ with no asm counterpart at that address → v1.1 drift
            drift_evidence.append({"src": f["name"], "addr": f["addr"], "asm": None})
        else:
            real_orphans.append(f["name"])

    # Compute stub count in src (FUN_/fn_-named function defs)
    src_stubs = sum(1 for f in c_funcs if STUB_NAME_RE.match(f["name"]))

    return {
        "asm_n": len(s_funcs),
        "src_n": len(c_funcs),
        "matched_n": len(matched_by_name),
        "asm_missing_in_src": sorted(asm_missing_in_src),
        "src_orphan_in_asm": sorted(src_orphan_in_asm),
        "drift_evidence": drift_evidence,
        "real_orphans": real_orphans,
        "src_stubs": src_stubs,
        "drift_score": len(drift_evidence) + len(asm_missing_in_src),
    }


def unit_source_path(unit_name: str) -> Path:
    """unit_name like 'main/main/dll/cannon' → src/main/dll/cannon.c."""
    # Strip leading "main/" (module name) once.
    parts = unit_name.split("/")
    if parts and parts[0] == "main":
        parts = parts[1:]
    rel = "/".join(parts) + ".c"
    return SRC / rel


def unit_asm_path(unit_name: str) -> Path:
    """unit_name like 'main/main/dll/cannon' → build/GSAE01/asm/main/dll/cannon.s."""
    parts = unit_name.split("/")
    if parts and parts[0] == "main":
        parts = parts[1:]
    rel = "/".join(parts) + ".s"
    return BUILD / "asm" / rel


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("unit", nargs="?", help="optional unit name (e.g. main/dll/cannon)")
    p.add_argument("--csv", action="store_true", help="emit CSV to stdout")
    p.add_argument("--only-drifted", action="store_true", help="hide aligned units")
    p.add_argument("--min-stubs", type=int, default=0, help="only show units with >= N stubs")
    p.add_argument("--max-units", type=int, default=200, help="cap output (default 200)")
    args = p.parse_args()

    report_path = BUILD / "report.json"
    if not report_path.is_file():
        sys.exit(f"missing {report_path} — run `ninja build/GSAE01/report.json` first")
    report = json.loads(report_path.read_text())

    rows: list[dict] = []
    for unit in report["units"]:
        meta = unit.get("metadata", {})
        if meta.get("auto_generated"):
            continue
        name = unit["name"]
        if "unknown/autos" in name:
            continue
        if args.unit and args.unit not in name:
            continue
        s_path = unit_asm_path(name)
        c_path = unit_source_path(name)
        if not s_path.is_file():
            continue
        s_funcs = parse_asm(s_path)
        c_funcs = parse_c(c_path)
        cls = classify(c_funcs, s_funcs)
        matched_pct = unit["measures"].get("matched_code_percent", 0.0)
        rows.append({
            "unit": name,
            "matched_pct": matched_pct,
            **cls,
            "c_path": str(c_path.relative_to(REPO)) if c_path.is_file() else "MISSING",
            "s_path": str(s_path.relative_to(REPO)),
        })

    # Sort: drifted first, then by drift_score desc, then by src_stubs desc.
    rows.sort(key=lambda r: (-r["drift_score"], -r["src_stubs"]))

    # Detail mode for a single unit.
    if args.unit and len(rows) == 1:
        r = rows[0]
        print(f"# Unit: {r['unit']}")
        print(f"# src:  {r['c_path']}")
        print(f"# asm:  {r['s_path']}")
        print(f"# matched: {r['matched_pct']:.2f}%  asm-funcs: {r['asm_n']}  src-funcs: {r['src_n']}  matched-by-name: {r['matched_n']}")
        print(f"# src-stubs (FUN_/fn_-named): {r['src_stubs']}  drift-score: {r['drift_score']}")
        if r["asm_missing_in_src"]:
            print("\n## asm symbols missing from src (add these as new fns):")
            for n in r["asm_missing_in_src"]:
                print(f"  - {n}")
        if r["drift_evidence"]:
            print("\n## drift evidence (src def at asm addr but wrong name OR no asm at addr):")
            for d in r["drift_evidence"]:
                addr = f"0x{d['addr']:08X}" if d["addr"] is not None else "?"
                asm = d["asm"] or "(no asm fn at this addr)"
                print(f"  - src '{d['src']}' @ {addr}  vs asm '{asm}'")
        if r["real_orphans"]:
            print("\n## src orphans (named functions w/o asm counterpart - often externally referenced):")
            for n in r["real_orphans"][:50]:
                print(f"  - {n}")
        return

    # Filter
    filtered = [r for r in rows if r["src_stubs"] >= args.min_stubs]
    if args.only_drifted:
        filtered = [r for r in filtered if r["drift_score"] > 0]
    filtered = filtered[: args.max_units]

    if args.csv:
        writer = csv.writer(sys.stdout)
        writer.writerow(["unit", "matched_pct", "asm_n", "src_n", "matched_n", "src_stubs", "drift_score", "asm_missing_n", "drift_evidence_n"])
        for r in filtered:
            writer.writerow([r["unit"], f"{r['matched_pct']:.2f}", r["asm_n"], r["src_n"], r["matched_n"],
                             r["src_stubs"], r["drift_score"], len(r["asm_missing_in_src"]), len(r["drift_evidence"])])
        return

    print(f"{'DRIFT':>5} {'STUBS':>5} {'PCT':>6} {'ASM':>4} {'SRC':>4} {'MATCH':>5}  UNIT")
    for r in filtered:
        print(f"{r['drift_score']:>5} {r['src_stubs']:>5} {r['matched_pct']:6.2f} {r['asm_n']:>4} {r['src_n']:>4} {r['matched_n']:>5}  {r['unit']}")


if __name__ == "__main__":
    main()
