"""Byte-level match gate for a single function: target .o vs current .o.

Exists because silence is ambiguous: several other tools in this repo print
NOTHING both when a function MATCHES and when the BUILD FAILED, so a sweep
that gates on empty output reports spurious matches.  This tool gates on
EXTRACTED FUNCTION BYTES and treats an empty/absent disassembly as a hard
ERROR, never as a match.

Usage:
  python3 tools/fnbytes.py <unit> <symbol>            MATCH / DIFF + first divergence
  python3 tools/fnbytes.py <unit> <symbol> --quiet    exit status only
  python3 tools/fnbytes.py <unit> <symbol> --md5      print both md5s
  python3 tools/fnbytes.py <unit> <symbol> --dump N   N instructions around each diff

Exit status: 0 MATCH, 1 DIFF, 2 ERROR (missing object, empty disassembly,
size mismatch on a symbol one side does not define).  A sweep MUST treat 2
as "no result", never as a pass.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import load_units

REPO = Path(__file__).resolve().parent.parent

INSN_RE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(\S+)(?:\s+(.*))?$")


def find_unit(units: list[dict], query: str) -> dict:
    """Resolve a unit by config name, report.json name, object path or basename.

    report.json calls a unit 'main/main/dll/x' where config.json calls it
    'main/dll/x.c'; accept either, and fall back to a unique basename hit.
    """
    query = query.replace("\\", "/")
    forms = {query, query + ".c"}
    if query.startswith("main/main/"):
        stripped = query[len("main/") :]
        forms |= {stripped, stripped + ".c"}
    for unit in units:
        name = unit["name"].replace("\\", "/")
        if name in forms or unit["object"].replace("\\", "/") in forms:
            return unit

    stem = Path(query).name.removesuffix(".c")
    hits = [u for u in units if Path(u["name"].replace("\\", "/")).name.removesuffix(".c") == stem]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise LookupError(f"ambiguous unit '{query}': " + ", ".join(u["name"] for u in hits))
    raise LookupError(f"unit not found: {query}")


def objdump_path() -> Path:
    for name in ("powerpc-eabi-objdump.exe", "powerpc-eabi-objdump"):
        candidate = REPO / "build" / "binutils" / name
        if candidate.is_file():
            return candidate
    raise SystemExit("ERROR: objdump not found under build/binutils")


def disassemble(objdump: Path, obj: Path, symbol: str) -> list[tuple[bytes, str]]:
    """Return [(4 bytes, 'mnem operands'), ...] for one symbol."""
    if not obj.is_file():
        raise LookupError(f"missing object: {obj}")
    proc = subprocess.run(
        [str(objdump), "-M", "gekko", "-drz", f"--disassemble={symbol}", str(obj)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise LookupError(f"objdump failed on {obj}: {proc.stderr.strip()[:200]}")

    out: list[tuple[bytes, str]] = []
    for line in proc.stdout.splitlines():
        match = INSN_RE.match(line)
        if not match:
            continue
        raw = bytes.fromhex(match.group(2).replace(" ", ""))
        text = match.group(3) + (" " + match.group(4).strip() if match.group(4) else "")
        out.append((raw, text))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("unit")
    parser.add_argument("symbol")
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--md5", action="store_true")
    parser.add_argument("--dump", type=int, default=0, metavar="N")
    args = parser.parse_args()

    config = REPO / "build" / args.version / "config.json"
    if not config.is_file():
        print(f"ERROR: missing config {config}", file=sys.stderr)
        return 2

    try:
        unit = find_unit(load_units(config), args.unit)
    except LookupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    target = REPO / Path(unit["object"])
    current = REPO / Path(
        unit["object"].replace(f"build/{args.version}/obj/", f"build/{args.version}/src/")
    )

    objdump = objdump_path()
    try:
        tgt = disassemble(objdump, target, args.symbol)
        cur = disassemble(objdump, current, args.symbol)
    except LookupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # The trap guard: an empty stream is NEVER a match.
    if not tgt:
        print(f"ERROR: no instructions for {args.symbol} in target {target}", file=sys.stderr)
        return 2
    if not cur:
        print(
            f"ERROR: no instructions for {args.symbol} in current {current} "
            "(build failed, symbol inlined away, or renamed)",
            file=sys.stderr,
        )
        return 2

    tgt_bytes = b"".join(b for b, _ in tgt)
    cur_bytes = b"".join(b for b, _ in cur)

    if args.md5:
        print(f"target  {hashlib.md5(tgt_bytes).hexdigest()}  {len(tgt_bytes)} B  {len(tgt)} insn")
        print(f"current {hashlib.md5(cur_bytes).hexdigest()}  {len(cur_bytes)} B  {len(cur)} insn")

    if tgt_bytes == cur_bytes:
        if not args.quiet:
            print(f"MATCH  {args.symbol}  {len(tgt_bytes)} B / {len(tgt)} insn")
        return 0

    diffs = [i for i in range(min(len(tgt), len(cur))) if tgt[i][0] != cur[i][0]]
    if args.quiet:
        return 1

    print(
        f"DIFF   {args.symbol}  target {len(tgt)} insn / current {len(cur)} insn  "
        f"positional diffs {len(diffs)}"
        + ("  SIZE MISMATCH" if len(tgt) != len(cur) else "")
    )
    if diffs:
        first = diffs[0]
        print(f"  first divergence at instruction {first} (offset 0x{first * 4:x}):")
        lo = max(0, first - args.dump)
        hi = min(min(len(tgt), len(cur)), first + args.dump + 1)
        for i in range(lo, hi):
            mark = "!" if tgt[i][0] != cur[i][0] else " "
            print(f"  {mark} [{i:4d}] target  {tgt[i][1]}")
            print(f"  {mark}        current {cur[i][1]}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
