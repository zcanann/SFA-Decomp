"""Normalized instruction diff for a single function: target .o vs current .o.

Masks branch-target addresses and groups divergences into regions, so output
shows only real codegen differences (not address/label noise). The classifier
pattern-matches each region against the CLAUDE.md recipe taxonomy and prints
the recipe numbers to try first.

Usage:
  python3 tools/ndiff.py <unit> <symbol>                normalized region diff
  python3 tools/ndiff.py <unit> <symbol> --classify     + recipe suggestions
  python3 tools/ndiff.py <unit> <symbol> --fingerprint 'fmuls|fadds'
        register-column fingerprint of matching instructions (probe batteries)
  python3 tools/ndiff.py <unit> <symbol> --context N    N matched instrs around
        each region (default 0)

Exit status: 0 if streams match (regions == 0), 1 otherwise.
"""
from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import load_units, resolve_unit, objdump_symbol, strip_preamble

INSTR_RE = re.compile(r"^[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\s*(.*)$")
LABEL_RE = re.compile(r"\b[0-9a-f]+ <[^>]+>")


def normalize(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        line = line.strip()
        m = INSTR_RE.match(line)
        if m:
            out.append(LABEL_RE.sub("LBL", m.group(1)).strip())
        elif "R_PPC" in line:
            out.append("RELOC " + line.split()[-1])
    return out


def regions(t: list[str], c: list[str]):
    sm = difflib.SequenceMatcher(None, t, c, autojunk=False)
    return [op for op in sm.get_opcodes() if op[0] != "equal"]


def mnemonics(instrs: list[str]) -> list[str]:
    return [i.split()[0] for i in instrs if i and not i.startswith("RELOC")]


def regs_only_diff(tt: list[str], cc: list[str]) -> bool:
    """True when both sides are the same opcodes/shapes with only rN/fN swapped."""
    if len(tt) != len(cc):
        return False
    strip = lambda s: re.sub(r"\b[rf]\d+\b", "R", s)
    return all(strip(a) == strip(b) for a, b in zip(tt, cc))


CLASSIFY_NOTE = {
    "ext-insert": "extra extsh/extsb/clrlwi in CURRENT -> narrow-extension class: "
    "#20 compound +=, #53 subtrahend cast, #83(c) drop cast on float store, "
    "#58 width launder, int-local keeper (dimmagicbridge) for the inverse",
    "ext-delete": "target HAS an extension we fold -> #83(c) INVERSE: route the copy "
    "through an int local to keep the conversion pair live",
    "reg-perm": "pure register permutation -> #16/#61b decl order, #61b fn-scope "
    "decl position, #107 un-naming, #82 launder, #88 web split; if a 'simplified' "
    "final iteration of uniform code, restore uniformity (mtx44_mult recipe)",
    "via-r0": "addi rX,rH,lo via r0+mr vs direct -> #80 init launder + arg respell, "
    "#160 index form for walked pointers",
    "branch-over-branch": "beq+b vs folded bne -> #109(d) single-case switch "
    "(SIGNED operands only; pointer/u8 operands are the documented wall), "
    "#13-addendum dead empty case, #63 keep-or-negate ternary",
    "cmp-width": "cmpwi vs cmplwi -> #3 (void*)/NULL, #14 int param, #58 width "
    "local, #64 (u32) cast in test, #11 vtable return width",
    "fcmpo-swap": "lfs pair + fcmpo operand swap -> #81 launder (*(f32 *)&lbl on "
    "ONE ref), double-embed clamp if (a = FIELD) op (lim = lbl), #82 taxonomy",
    "frame": "stwu/frame delta -> #67 (probe array sizes, struct-typed locals, "
    "conversion slots), #75 union align, #109(e) struct slot",
    "pool-reloc": "@N vs named lbl reloc -> score-neutral per #70 UNLESS the "
    "score is <100: then check #71 literal-vs-extern reload shape",
    "mr-copy": "mr/fmr copy inserted or deleted -> #68 peephole copy-prop "
    "(A/B peephole pragma), #86 emission order, #119 variable recycling",
    "lha-lhz": "lha vs lhz -> s16/u16 signedness of field or deref (#46/#58)",
    "li-const": "li constant materialization differs -> #74 LL-suffix masks, "
    "#110 per-fn O1 for li;mr chains, #51 chained assignment, GVN small-const "
    "open class (bank if spellings exhausted)",
    "sched-order": "same instructions transposed -> scheduling/emission order: "
    "#5 decl/init split, #43 comma-init, #116 embedded store address, #29/#84 "
    "arg eval order, #90 doubled-arg launder",
    "deref-via-copy": "param deref via saved-reg copy in TARGET, via param reg in "
    "CURRENT -> #68 peephole copy-prop: wrap fn in #pragma peephole off (or check "
    "the unit's effective pragma state first; ON-target units are NOT this class). "
    "Non-r3-param variant is documented open",
}


def classify(tt: list[str], cc: list[str]) -> str:
    tm, cm = mnemonics(tt), mnemonics(cc)
    ext = {"extsh", "extsb", "clrlwi"}
    if not tm and not cm:
        joined = " ".join(tt + cc)
        return "pool-reloc" if "RELOC" in joined else ""
    if not tm and cm and set(cm) <= ext:
        return "ext-insert"
    if not cm and tm and set(tm) <= ext:
        return "ext-delete"
    if set(cm) - set(tm) <= ext and len(cm) > len(tm) and set(cm) & ext:
        return "ext-insert"
    if set(tm) - set(cm) <= ext and len(tm) > len(cm) and set(tm) & ext:
        return "ext-delete"
    joined_t, joined_c = " | ".join(tt), " | ".join(cc)
    if "RELOC @" in joined_c and "RELOC lbl" in joined_t and len(tt) == len(cc) == 1:
        return "pool-reloc"
    if ("mr " in joined_c or "fmr" in joined_c) != ("mr " in joined_t or "fmr" in joined_t):
        if abs(len(tm) - len(cm)) <= 1 and ("mr" in tm + cm or "fmr" in tm + cm):
            return "mr-copy"
    if "stwu" in tm + cm:
        return "frame"
    if ("cmpwi" in tm and "cmplwi" in cm) or ("cmplwi" in tm and "cmpwi" in cm):
        return "cmp-width"
    if ("lha" in tm and "lhz" in cm) or ("lhz" in tm and "lha" in cm):
        return "lha-lhz"
    if "fcmpo" in tm or "fcmpu" in tm:
        if regs_only_diff(tt, cc):
            return "fcmpo-swap"
    if regs_only_diff(tt, cc) and len(tt) == 1:
        m = re.search(r"\((r\d+)\)", tt[0]), re.search(r"\((r\d+)\)", cc[0])
        if m[0] and m[1]:
            treg, creg = int(m[0].group(1)[1:]), int(m[1].group(1)[1:])
            if treg >= 14 and creg <= 10:
                return "deref-via-copy"
    if ("beq" in tm and "b" in tm and "bne" in cm) or ("beq" in cm and "b" in cm and "bne" in tm):
        return "branch-over-branch"
    if "addi" in cm and "mr" in cm and "addi" in tm and "mr" not in tm:
        return "via-r0"
    if "li" in tm and "li" in cm and regs_only_diff(tt, cc):
        return "reg-perm"
    if tm and cm and sorted(tm) == sorted(cm) and tm != cm:
        return "sched-order"
    if regs_only_diff(tt, cc):
        return "reg-perm"
    if "li" in tm or "li" in cm:
        return "li-const"
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("unit")
    parser.add_argument("symbol")
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--classify", action="store_true", help="suggest recipes per region")
    parser.add_argument("--fingerprint", metavar="REGEX",
                        help="print operand columns of CURRENT instrs matching REGEX (and target's)")
    parser.add_argument("--context", type=int, default=0, metavar="N",
                        help="show N matched instructions around each region")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    config_path = repo_root / "build" / args.version / "config.json"
    objdump_path = repo_root / "build" / "binutils" / "powerpc-eabi-objdump"
    if not objdump_path.is_file():
        objdump_path = repo_root / "build" / "binutils" / "powerpc-eabi-objdump.exe"

    unit = resolve_unit(load_units(config_path), args.unit)
    target_object = repo_root / Path(unit["object"])
    current_object = repo_root / Path(
        unit["object"].replace(f"build/{args.version}/obj/", f"build/{args.version}/src/"))

    t = normalize(strip_preamble(objdump_symbol(objdump_path, target_object, args.symbol)))
    c = normalize(strip_preamble(objdump_symbol(objdump_path, current_object, args.symbol)))
    if not t:
        raise SystemExit(f"Symbol {args.symbol} not found in target object")
    if not c:
        raise SystemExit(f"Symbol {args.symbol} not found in current object")

    if args.fingerprint:
        rx = re.compile(args.fingerprint)
        fp = lambda ls: " ".join(i.split(None, 1)[1] if " " in i else i
                                 for i in ls if not i.startswith("RELOC") and rx.search(i))
        print("T:", fp(t))
        print("C:", fp(c))
        return

    regs = regions(t, c)
    for tag, i1, i2, j1, j2 in regs:
        tt, cc = t[i1:i2], c[j1:j2]
        if args.context:
            n = args.context
            print(f"  ...{t[max(0, i1 - n):i1]}")
        print(f"{tag:7s} T: {tt}")
        print(f"        C: {cc}")
        if args.context:
            print(f"  ...{t[i2:i2 + args.context]}")
        if args.classify:
            kind = classify(tt, cc)
            if kind:
                print(f"  >> [{kind}] {CLASSIFY_NOTE[kind]}")
        if args.classify or args.context:
            print()
    print(f"-- {len(regs)} region(s), T={len(t)} C={len(c)} instrs")
    sys.exit(0 if not regs else 1)


if __name__ == "__main__":
    main()
