"""Probe-battery harness: compile source variants of one function against the
unit's exact MWCC flags and score each against the target instruction stream.

This automates the /tmp probe workflow that cracked recipes #74/#80/#83/#107
and mtx44_mult: extract a function into a standalone probe dir, write N
spelling variants, and compare register/instruction fingerprints in one shot.

Workflow:
  1. python3 tools/probe_battery.py extract <unit> <symbol> --out /tmp/probe
       Writes base.c (function slice + decl stub header to hand-fix),
       flags.txt (the unit's exact mwcc invocation), target.s (normalized
       target asm). Edit base.c until it compiles and `run` shows your
       in-tree divergence (a faithful repro), then copy base.c to v1.c,
       v2.c ... and vary spellings.
  2. python3 tools/probe_battery.py run --dir /tmp/probe [--fp REGEX]
       Compiles every *.c in the dir, prints one line per variant:
       region count vs target + first divergence (or REGEX fingerprint).

Caveats (from CLAUDE.md): carry the unit's pragma state into the probe (#113
probe-trap); some divergences are fn-global and do NOT reproduce standalone
(#108 dose classes) — if base.c compiles clean against target but the in-tree
fn diverges, the divergence is context-bound: stop probing, A/B in-tree.
"""
from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import load_units, resolve_unit, objdump_symbol, strip_preamble
from ndiff import normalize

REPO = Path(__file__).resolve().parent.parent


def ninja_flags(unit_obj: str) -> tuple[str, str]:
    """Return (mw_version, cflags) for a unit object path from build.ninja."""
    text = (REPO / "build.ninja").read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith(f"build {unit_obj}:"):
            start = i
            break
    if start is None:
        raise SystemExit(f"No build edge for {unit_obj} in build.ninja")

    block = []
    i = start
    while i < len(lines):
        block.append(lines[i])
        if not lines[i].rstrip().endswith("$") and i > start and not lines[i].startswith(("  ", "build")):
            break
        i += 1
        if i < len(lines) and lines[i].startswith("build "):
            break

    joined = []
    for line in block:
        joined.append(line.rstrip().rstrip("$").rstrip())
    blob = "\n".join(joined)

    mw = re.search(r"mw_version = (\S+)", blob)
    cf = re.search(r"cflags = (.*?)(?:\n  \w+ =|\Z)", blob, re.S)
    if not mw or not cf:
        raise SystemExit("Could not parse mw_version/cflags from build edge")
    cflags = " ".join(cf.group(1).split())
    cflags = re.sub(r"\s*-MMD\b", "", cflags)
    return mw.group(1), cflags


def extract_fn(source: Path, symbol: str) -> str:
    text = source.read_text(encoding="utf-8", errors="replace")
    m = re.search(rf"^[A-Za-z_][\w \t\*]*\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{",
                  text, re.M)
    if not m:
        raise SystemExit(f"Definition of {symbol} not found in {source}")
    depth, i = 0, m.start()
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():i + 1]
        i += 1
    raise SystemExit("Unbalanced braces")


def compile_probe(cfile: Path, mw_version: str, cflags: str) -> Path:
    ofile = cfile.with_suffix(".o")
    cmd = (f"build/tools/wibo build/compilers/{mw_version}/mwcceppc.exe "
           f"{cflags} -c {cfile} -o {ofile}")
    r = subprocess.run(cmd, shell=True, cwd=REPO, capture_output=True, text=True)
    if not ofile.is_file():
        sys.stderr.write(r.stdout + r.stderr)
        return None
    return ofile


def probe_asm(ofile: Path, symbol: str) -> list[str]:
    objdump = REPO / "build" / "binutils" / "powerpc-eabi-objdump"
    if not objdump.is_file():
        objdump = REPO / "build" / "binutils" / "powerpc-eabi-objdump.exe"
    return normalize(strip_preamble(objdump_symbol(objdump, ofile, symbol)))


def cmd_extract(args) -> None:
    config_path = REPO / "build" / args.version / "config.json"
    unit = resolve_unit(load_units(config_path), args.unit)
    target_object = REPO / Path(unit["object"])
    unit_src_obj = unit["object"].replace(f"build/{args.version}/obj/",
                                          f"build/{args.version}/src/")
    mw, cflags = ninja_flags(unit_src_obj)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    t = probe_asm(target_object, args.symbol)
    if not t:
        raise SystemExit(f"{args.symbol} not in target object")
    (out / "target.s").write_text("\n".join(t) + "\n")

    src_path = None
    name = unit["name"].replace("\\", "/")
    cand = REPO / "src" / Path(name).relative_to(Path(name).parts[0])
    if cand.is_file():
        src_path = cand
    else:
        stem = Path(name).stem
        hits = list((REPO / "src").rglob(stem + ".c"))
        if len(hits) == 1:
            src_path = hits[0]
    fn = extract_fn(src_path, args.symbol) if src_path else f"/* paste {args.symbol} here */"

    (out / "base.c").write_text(
        "/* probe for " + args.symbol + " from " + (str(src_path) if src_path else "?") +
        "\n   ADD the decls/typedefs this fn needs and the unit's PRAGMA state\n"
        "   (see CLAUDE.md #113 probe-trap), then `run` until base.c reproduces\n"
        "   the in-tree divergence. */\n"
        "typedef float f32;\ntypedef double f64;\ntypedef int s32;\n"
        "typedef unsigned int u32;\ntypedef short s16;\ntypedef unsigned short u16;\n"
        "typedef signed char s8;\ntypedef unsigned char u8;\n\n" + fn + "\n")
    (out / "flags.txt").write_text(mw + "\n" + cflags + "\n")
    (out / "symbol.txt").write_text(args.symbol + "\n")
    print(f"probe dir ready: {out}")
    print(f"  mw_version: {mw}")
    print(f"  next: edit {out / 'base.c'} until it compiles, then")
    print(f"        python3 tools/probe_battery.py run --dir {out}")


def cmd_run(args) -> None:
    d = Path(args.dir)
    mw, cflags = (d / "flags.txt").read_text().splitlines()[:2]
    symbol = (d / "symbol.txt").read_text().strip()
    target = (d / "target.s").read_text().splitlines()

    rx = re.compile(args.fp) if args.fp else None
    if rx:
        fp = lambda ls: " ".join(i.split(None, 1)[1] if " " in i else i
                                 for i in ls if not i.startswith("RELOC") and rx.search(i))
        print("TARGET:", fp(target))

    for cfile in sorted(d.glob("*.c")):
        ofile = compile_probe(cfile, mw, cflags)
        if ofile is None:
            print(f"{cfile.name}: COMPILE FAIL")
            continue
        cur = probe_asm(ofile, symbol)
        if not cur:
            print(f"{cfile.name}: symbol {symbol} missing from probe .o")
            continue
        if rx:
            print(f"{cfile.name}: {fp(cur)}")
            continue
        sm = difflib.SequenceMatcher(None, target, cur, autojunk=False)
        regs = [op for op in sm.get_opcodes() if op[0] != "equal"]
        if not regs:
            print(f"{cfile.name}: MATCH ({len(cur)} instrs)")
        else:
            tag, i1, i2, j1, j2 = regs[0]
            print(f"{cfile.name}: {len(regs)} region(s)  T={len(target)} C={len(cur)}  "
                  f"first: T{target[i1:i2][:3]} C{cur[j1:j2][:3]}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    pe = sub.add_parser("extract", help="set up a probe dir for unit/symbol")
    pe.add_argument("unit")
    pe.add_argument("symbol")
    pe.add_argument("--out", required=True)
    pe.add_argument("-v", "--version", default="GSAE01")
    pe.set_defaults(func=cmd_extract)
    pr = sub.add_parser("run", help="compile all *.c variants and score vs target")
    pr.add_argument("--dir", required=True)
    pr.add_argument("--fp", metavar="REGEX", help="fingerprint mode: operand columns of matching instrs")
    pr.set_defaults(func=cmd_run)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
