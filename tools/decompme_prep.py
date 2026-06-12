#!/usr/bin/env python3
"""Prep paste-ready decomp.me scratch inputs for one function — no network.

decomp.me's GC/Wii scratch form has four inputs. This gathers all four from
the build tree so you only paste (never hand-copy from objdump/headers):

  1. Target asm  -> the dtk disassembly slice for the function, comments
                    stripped, keeping real symbol refs (foo@sda21) and .L_
                    labels that decomp.me's assembler resolves.
  2. Context     -> the unit's decompctx output (build/.../<unit>.ctx),
                    built via ninja if missing. Paste whole.
  3. Source      -> best-effort slice of the function body from the .c.
  4. Compiler    -> GC/2.0 maps to decomp.me id `mwcc_242_81`, platform
                    gc_wii; flags lifted verbatim from build.ninja.

Usage:
  python3 tools/decompme_prep.py <symbol> [--unit <unit-substr>] [--out DIR]

<symbol> alone is enough when it is unique project-wide. --unit disambiguates.
Writes <out>/{target.s,context.c,source.c,fields.txt}; prints the field map.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "build" / "GSAE01" / "config.json"

# decomp.me compiler id per mwcc version (GC/Wii platform = gc_wii).
DECOMPME_COMPILER = {
    "GC/1.0": "mwcc_233_144",
    "GC/1.1": "mwcc_233_159",
    "GC/1.2.5": "mwcc_233_163",
    "GC/1.2.5n": "mwcc_233_163n",
    "GC/1.3": "mwcc_233_163",
    "GC/1.3.2": "mwcc_242_53",
    "GC/2.0": "mwcc_242_81",
    "GC/2.5": "mwcc_247_92",
    "GC/2.6": "mwcc_247_105",
    "GC/2.7": "mwcc_247_107",
}


def load_unit(symbol: str, unit_hint: str | None) -> dict:
    units = json.loads(CONFIG.read_text())["units"]
    cands = units
    if unit_hint:
        cands = [u for u in units if unit_hint in u["name"]]
    # Narrow to units whose asm actually defines the symbol.
    matches = []
    for u in cands:
        asm = REPO / "build" / "GSAE01" / "asm" / (Path(u["name"]).with_suffix(".s").as_posix())
        if asm.exists() and re.search(rf"^\.fn {re.escape(symbol)},", asm.read_text(errors="replace"), re.M):
            matches.append(u)
    if not matches:
        raise SystemExit(f"No unit defines .fn {symbol} (try --unit). config={CONFIG}")
    if len(matches) > 1:
        raise SystemExit("Ambiguous; pass --unit. Candidates: "
                         + ", ".join(u["name"] for u in matches))
    return matches[0]


def asm_slice(unit: dict, symbol: str) -> str:
    asm = REPO / "build" / "GSAE01" / "asm" / (Path(unit["name"]).with_suffix(".s").as_posix())
    out, grab = [], False
    for line in asm.read_text(errors="replace").splitlines():
        if re.match(rf"^\.fn {re.escape(symbol)},", line):
            grab = True
        if grab:
            # Strip the dtk "/* addr addr bytes */" prefix -> clean asm.
            out.append(re.sub(r"^/\*.*?\*/\t?", "", line).rstrip())
        if grab and line.startswith(f".endfn {symbol}"):
            break
    return "\n".join(out) + "\n"


def build_ctx(unit: dict) -> Path:
    ctx = REPO / "build" / "GSAE01" / "src" / (Path(unit["name"]).with_suffix(".ctx").as_posix())
    if not ctx.exists():
        subprocess.run(["ninja", ctx.relative_to(REPO).as_posix()], cwd=REPO, check=True)
    return ctx


def flags(unit: dict) -> tuple[str, str]:
    # Reuse probe_battery's verified ninja parser.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from probe_battery import ninja_flags
    # build.ninja's edge is the compiled object under src/, not the dtk target obj/.
    compiled = f"build/GSAE01/src/{Path(unit['name']).with_suffix('.o').as_posix()}"
    return ninja_flags(compiled)


def src_path(unit: dict) -> Path:
    """config unit names are repo-relative under src/ (e.g. main/dll/...)."""
    p = REPO / unit["name"]
    if not p.exists():
        p = REPO / "src" / unit["name"]
    return p


def source_slice(unit: dict, symbol: str) -> str:
    src = src_path(unit)
    if not src.exists():
        return f"/* source not found: {src} — paste your function here */\n"
    text = src.read_text(errors="replace")
    # Find a line that looks like the definition opener for `symbol`.
    m = re.search(rf"(?m)^[\w \t\*\(\)]*\b{re.escape(symbol)}\s*\([^;{{]*\)\s*\{{", text)
    if not m:
        return (f"/* could not auto-slice {symbol} from {src.name}; open it and "
                f"copy the body. */\n")
    start = text.rfind("\n", 0, m.start()) + 1
    i, depth, started = m.end() - 1, 0, False
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1; started = True
        elif c == "}":
            depth -= 1
            if started and depth == 0:
                i += 1; break
        i += 1
    return text[start:i] + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("symbol")
    ap.add_argument("--unit", help="substring to disambiguate the unit")
    ap.add_argument("--out", default=None, help="output dir (default /tmp/decompme_<symbol>)")
    args = ap.parse_args()

    unit = load_unit(args.symbol, args.unit)
    out = Path(args.out or f"/tmp/decompme_{args.symbol}")
    out.mkdir(parents=True, exist_ok=True)

    (out / "target.s").write_text(asm_slice(unit, args.symbol))
    ctx = build_ctx(unit)
    (out / "context.c").write_text(ctx.read_text(errors="replace"))
    (out / "source.c").write_text(source_slice(unit, args.symbol))
    ver, cf = flags(unit)
    compiler = DECOMPME_COMPILER.get(ver, "mwcc_242_81")
    (out / "fields.txt").write_text(
        f"# decomp.me scratch — {args.symbol}\n"
        f"Platform:        gc_wii\n"
        f"Compiler:        {compiler}   (mwcc {ver})\n"
        f"Diff label:      {args.symbol}\n"
        f"Compiler flags:\n{cf}\n\n"
        f"Paste into the form:\n"
        f"  Target asm box   <- target.s\n"
        f"  Context box      <- context.c\n"
        f"  Source box       <- source.c\n"
    )

    print(f"unit:     {unit['name']}")
    print(f"out:      {out}/")
    print(f"  target.s   ({(out/'target.s').stat().st_size} B)  -> decomp.me 'Target asm'")
    print(f"  context.c  ({(out/'context.c').stat().st_size} B)  -> decomp.me 'Context'")
    print(f"  source.c   ({(out/'source.c').stat().st_size} B)  -> decomp.me 'Source'")
    print(f"\nplatform: gc_wii")
    print(f"compiler: {compiler}   (mwcc {ver})")
    print(f"flags:    {cf}")
    print(f"\nNew scratch: https://decomp.me/scratch/new   (or paste the 3 files above)")


if __name__ == "__main__":
    main()
