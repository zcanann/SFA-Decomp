#!/usr/bin/env python3
"""multiset.py <unit> <sym> [--classify]

Prints the T-only / C-only mnemonic-multiset delta between the retail target
object and our built .o for one function, and (with --classify) labels the delta
per the banked two-factor-interaction laws so the isolated-ext-insert vein can be
screened without a full build.

UNIT NAME GOTCHA: <unit> is resolved by function_objdump.resolve_unit, which
matches config.json unit names -- these carry the ".c" suffix
(e.g. "dll_0261_drlasercannon.c" or "main/dll/DR/dll_0261_drlasercannon.c").
report.json's unit name is the DOUBLED-prefix form ("main/main/dll/DR/...") and
is NOT what this tool wants. To go report -> config: strip the leading "main/",
append ".c" (basename also works).

CLASSIFY LABELS (operates on the mnemonic delta only):
  PURE-REG-PERM      empty delta  -- register permutation OR pool-reloc-only; cap.
  EXT-HANDLE-T       lone extsh/extsb the TARGET has and we lack -- the paying
                     "insert a cast" direction (objseq's ext-insert vein).
  EXT-HANDLE-C       lone extsh/extsb WE emit spuriously -- usually a peephole
                     product (sandworm family); removal has no clean-C source.
  SIGNEDNESS-HANDLE  srawi<->clrlwi or clrlwi<->addi swap -- signedness handle.
  ZERO-REUSE-CAP     li<->mr swap -- the zero-reuse coloring cap.
  BRANCH-SENSE       lone beq<->bne / bge<->ble / blt<->bgt swap.
  MIXED              anything else (ext coupled to mr/branch/other = NOT isolated).

Only EXT-HANDLE-T and SIGNEDNESS-HANDLE with an ISOLATED delta (no mr/branch/
other keys, |delta| small) are candidates for the isolated-ext-insert vein.
"""
import sys
import re
import subprocess
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import (
    load_units,
    resolve_unit,
    objdump_symbol,
    strip_preamble,
)

INSTR = re.compile(r"^[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\s*(.*)$")

EXT_MNEMS = {"extsh", "extsb"}
SIGNED_NARROW = {"srawi", "extsb", "extsh"}
UNSIGNED_NARROW = {"clrlwi", "addi"}
ZERO_MNEMS = {"li", "mr"}
BRANCH_PAIRS = [
    {"beq", "bne"},
    {"bge", "ble"},
    {"blt", "bgt"},
    {"bgt", "blt"},
    {"blt", "bge"},
    {"bgt", "ble"},
]


def mnem_counts(lines):
    c = Counter()
    for ln in lines:
        m = INSTR.match(ln.strip())
        if not m:
            continue
        c[m.group(1).split(None, 1)[0]] += 1
    return c


def deltas(ct, cc):
    extra_t = {k: ct[k] - cc[k] for k in ct if ct[k] > cc[k]}
    extra_c = {k: cc[k] - ct[k] for k in cc if cc[k] > ct[k]}
    return extra_t, extra_c


def classify(extra_t, extra_c):
    keys = set(extra_t) | set(extra_c)
    if not keys:
        return "PURE-REG-PERM", False
    total = sum(extra_t.values()) + sum(extra_c.values())

    # lone ext handle (extsh/extsb the target has and we lack, or vice versa)
    if keys <= EXT_MNEMS and total <= 2:
        if extra_t and not extra_c:
            return "EXT-HANDLE-T", True
        if extra_c and not extra_t:
            return "EXT-HANDLE-C", False
    # signedness swap: signed-narrow <-> unsigned-narrow, isolated (no other keys),
    # both sides non-empty (a true swap, not a lone add/remove), small magnitude.
    if (
        keys <= (SIGNED_NARROW | UNSIGNED_NARROW)
        and extra_t
        and extra_c
        and total <= 4
    ):
        return "SIGNEDNESS-HANDLE", True
    # zero reuse
    if keys == ZERO_MNEMS:
        return "ZERO-REUSE-CAP", False
    # branch sense
    if keys in BRANCH_PAIRS and total <= 2:
        return "BRANCH-SENSE", False
    return "MIXED", False


def analyze(unit_query, sym):
    units = load_units(Path("build/GSAE01/config.json"))
    unit = resolve_unit(units, unit_query)
    objdump = Path("build/binutils/powerpc-eabi-objdump")
    obj = Path(unit["object"])
    src_obj = Path(unit["object"].replace("/obj/", "/src/"))
    tgt = strip_preamble(objdump_symbol(objdump, obj, sym))
    cur = strip_preamble(objdump_symbol(objdump, src_obj, sym))
    return deltas(mnem_counts(tgt), mnem_counts(cur))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    do_classify = "--classify" in sys.argv[1:]
    if len(args) < 2:
        raise SystemExit("usage: multiset.py <unit> <sym> [--classify]")
    unit_query, sym = args[0], args[1]
    extra_t, extra_c = analyze(unit_query, sym)
    if do_classify:
        label, promising = classify(extra_t, extra_c)
        flag = "PROMISING" if promising else ""
        print(
            f"{sym}: {label} {flag}  T-only={extra_t} C-only={extra_c}".rstrip()
        )
    elif extra_t or extra_c:
        print(f"{sym}: T-only={extra_t} C-only={extra_c}")


if __name__ == "__main__":
    main()
