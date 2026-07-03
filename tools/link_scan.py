#!/usr/bin/env python3
"""Find units that are safe to flip NonMatching -> MatchingFor (i.e. that will
link byte-identically into main.dol).

A 100% objdiff match is necessary but NOT sufficient to link: objdiff compares
sections symbol-by-symbol and ignores whole-object concerns that decide the
final link. This scanner adds the checks objdiff doesn't:

  1. Section parity  - the built object must have the same allocated sections
     (.text/.data/.rodata/.sdata/.sdata2/.bss/...) as the retail object, with
     identical sizes AND identical bytes for non-bss sections. (Catches the
     "built object emits an extra .data" class that shifts the whole DOL.)
  2. Reloc safety    - every undefined symbol the built object references must
     be a globally-resolvable name in symbols.txt. (Catches source that still
     references a synthetic `lbl_ADDR`/`fn_ADDR` label the linker can't find.)

What it CANNOT predict: cross-object common-symbol / bss merge shifts. Two
objects can pass every check above and still move the .bss/.sdata base by a few
bytes once linked together. The DOL SHA1 (`ninja build/GSAE01/ok`) is the only
ground truth - always flip a batch, link, and bisect any failure.

Usage:
    python3 tools/link_scan.py                 # print candidate source paths
    python3 tools/link_scan.py --explain       # also print why others were rejected
"""
import argparse
import json
import os
import re
import subprocess

BUILD = "build/GSAE01"
OBJDUMP = "build/binutils/powerpc-eabi-objdump"
IGNORE_SECTIONS = {".comment", ".symtab", ".strtab", ".shstrtab", ".note.split"}
BSS_SECTIONS = {".bss", ".sbss", ".sbss2"}


def section_sizes(obj):
    out = subprocess.run([OBJDUMP, "-h", obj], capture_output=True, text=True).stdout
    sizes = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 7 and p[0].isdigit():
            name = p[1]
            if name in IGNORE_SECTIONS or name.startswith(".debug") or name.startswith(".mwcats"):
                continue
            sizes[name] = int(p[2], 16)
    return sizes


def section_bytes(obj, name):
    tmp = "/tmp/_link_scan_sec.bin"
    subprocess.run(
        ["build/binutils/powerpc-eabi-objcopy", "-O", "binary", f"--only-section={name}", obj, tmp],
        capture_output=True,
    )
    try:
        return open(tmp, "rb").read()
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def undefined_syms(obj):
    out = subprocess.run([OBJDUMP, "-t", obj], capture_output=True, text=True).stdout
    return [line.split()[-1] for line in out.splitlines() if "*UND*" in line]


def resolvable_names():
    names = set()
    scope_re = re.compile(r"scope:(\w+)")
    for line in open(f"config/GSAE01/symbols.txt"):
        if " = " not in line:
            continue
        name = line.split(" = ", 1)[0].strip()
        m = scope_re.search(line)
        if (m.group(1) if m else "global") in ("global", "weak"):
            names.add(name)
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--explain", action="store_true", help="print rejection reasons")
    args = ap.parse_args()

    report = json.load(open(f"{BUILD}/report.json"))
    resolvable = resolvable_names()

    good, rejected = [], []
    for u in report["units"]:
        md = u["metadata"]
        if md.get("auto_generated") or md.get("complete"):
            continue
        sp = md.get("source_path")
        if not sp or u["measures"].get("fuzzy_match_percent") != 100.0:
            continue
        rel = sp[4:] if sp.startswith("src/") else sp
        built = f"{BUILD}/src/{rel[:-2]}.o"
        orig = f"{BUILD}/obj/{rel[:-2]}.o"
        if not (os.path.exists(built) and os.path.exists(orig)):
            rejected.append((sp, "no-object"))
            continue
        sb, so = section_sizes(built), section_sizes(orig)
        if sb != so:
            rejected.append((sp, f"section-size {sb} vs {so}"))
            continue
        if any(
            name not in BSS_SECTIONS and section_bytes(built, name) != section_bytes(orig, name)
            for name in sb
        ):
            rejected.append((sp, "section-bytes"))
            continue
        bad = [s for s in undefined_syms(built) if s not in resolvable]
        if bad:
            rejected.append((sp, f"unresolved {bad[:3]}"))
            continue
        good.append(sp)

    for sp in good:
        print(sp)
    if args.explain:
        print(f"\n# {len(good)} candidates, {len(rejected)} rejected", flush=True)
        for sp, why in rejected:
            print(f"# reject {sp}: {why}")


if __name__ == "__main__":
    main()
