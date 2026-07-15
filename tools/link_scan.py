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
  3. Symbol layout   - linker-visible symbols must retain their retail section,
     offset, and size. (Catches equal-sized BSS blocks with a different internal
     allocation order.)
  4. BSS retention  - a source BSS section with no retail relocation users must
     be explicitly force-active. (Catches compiled allocations that the linker
     otherwise dead-strips.)

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
import tempfile

BUILD = "build/GSAE01"
EXE_SUFFIX = ".exe" if os.name == "nt" else ""
OBJDUMP = os.path.abspath(f"build/binutils/powerpc-eabi-objdump{EXE_SUFFIX}")
OBJCOPY = os.path.abspath(f"build/binutils/powerpc-eabi-objcopy{EXE_SUFFIX}")
IGNORE_SECTIONS = {".comment", ".symtab", ".strtab", ".shstrtab", ".note.split"}
BSS_SECTIONS = {".bss", ".sbss", ".sbss2"}
ALLOC_SECTIONS = {
    ".text",
    ".ctors",
    ".dtors",
    ".rodata",
    ".data",
    ".bss",
    ".sdata",
    ".sbss",
    ".sdata2",
    ".sbss2",
    "extab",
    "extabindex",
}


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


def section_alignments(obj):
    out = subprocess.run([OBJDUMP, "-h", obj], capture_output=True, text=True).stdout
    alignments = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 7 and p[0].isdigit():
            name = p[1]
            if name in IGNORE_SECTIONS or name.startswith(".debug") or name.startswith(".mwcats"):
                continue
            if p[6].startswith("2**"):
                alignments[name] = 1 << int(p[6][3:])
    return alignments


def section_bytes(obj, name):
    fd, tmp = tempfile.mkstemp(prefix="link_scan_sec_", suffix=".bin")
    os.close(fd)
    subprocess.run(
        [OBJCOPY, "-O", "binary", f"--only-section={name}", obj, tmp],
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


def defined_symbol_layout(obj, known_names):
    """Return linker-visible symbol placement for names owned by this unit.

    Whole-section byte equality is insufficient for BSS: two objects can have
    the same total BSS size while assigning different offsets to the symbols
    inside it.  The linker resolves relocations by symbol, so that layout must
    match too.
    """
    out = subprocess.run([OBJDUMP, "-t", obj], capture_output=True, text=True).stdout
    layout = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        name = parts[-1]
        section = parts[-3]
        if name not in known_names or section not in ALLOC_SECTIONS:
            continue
        try:
            layout[name] = (section, int(parts[0], 16), int(parts[-2], 16))
        except ValueError:
            continue
    return layout


def defined_symbol_locations(obj):
    out = subprocess.run([OBJDUMP, "-t", obj], capture_output=True, text=True).stdout
    locations = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        name = parts[-1]
        section = parts[-3]
        if section not in ALLOC_SECTIONS:
            continue
        try:
            locations[name] = (section, int(parts[0], 16))
        except ValueError:
            continue
    return locations


def relocation_base(value):
    return re.split(r"(?=[+-]0x)", value, maxsplit=1)[0]


def section_bases(obj, addresses):
    candidates = {}
    for name, (section, offset) in defined_symbol_locations(obj).items():
        if name in addresses:
            candidates.setdefault(section, set()).add(addresses[name] - offset)
    return {
        section: next(iter(values))
        for section, values in candidates.items()
        if len(values) == 1
    }


def relocation_layout(obj, addresses, bases):
    out = subprocess.run([OBJDUMP, "-r", obj], capture_output=True, text=True).stdout
    symbols = defined_symbol_locations(obj)
    section = None
    layout = []
    section_re = re.compile(r"^RELOCATION RECORDS FOR \[(.+)\]:$")
    reloc_re = re.compile(r"^\s*([0-9A-Fa-f]+)\s+(R_\S+)\s+(\S+)\s*$")
    for line in out.splitlines():
        match = section_re.match(line)
        if match:
            section = match.group(1)
            continue
        match = reloc_re.match(line)
        if match is None or section is None:
            continue
        if section in {"extab", "extabindex"}:
            continue
        offset = int(match.group(1), 16)
        kind = match.group(2)
        if section == ".text":
            offset &= ~3
        value = match.group(3)
        base = relocation_base(value)
        suffix = value[len(base):]
        addend = int(suffix, 0) if suffix else 0
        if base in symbols:
            target_section, target_offset = symbols[base]
            if target_section in bases:
                target = ("address", bases[target_section] + target_offset + addend)
            else:
                target = (target_section, target_offset + addend)
        elif base in addresses:
            target = ("address", addresses[base] + addend)
        else:
            target = (base, addend)
        layout.append((section, offset, kind, target))
    return sorted(layout)


def relocation_referrers():
    """Collect symbols referenced by retail input relocations.

    DTK's retail split objects are force-exported, while a compiled source
    object can lose a wholly unreferenced BSS section during the final link.
    An unreferenced source BSS section therefore is not promotion-safe even
    when its raw size and symbol layout match the retail object.
    """
    refs = {}
    reloc_re = re.compile(r"^\s*[0-9A-Fa-f]+\s+R_\S+\s+(\S+)")
    object_re = re.compile(r"^(.+\.o):\s+file format\s+")
    config = json.load(open(f"{BUILD}/config.json"))
    objects = [unit["object"] for unit in config["units"]]
    fd, rsp = tempfile.mkstemp(prefix="link_scan_objdump_", suffix=".rsp", text=True)
    try:
        with os.fdopen(fd, "w") as f:
            for obj in objects:
                f.write(f'"{os.path.abspath(obj)}"\n')
        out = subprocess.run(
            [OBJDUMP, "-r", f"@{rsp}"], capture_output=True, text=True
        ).stdout
    finally:
        if os.path.exists(rsp):
            os.remove(rsp)
    current_obj = None
    for line in out.splitlines():
        match = object_re.match(line)
        if match:
            current_obj = os.path.abspath(match.group(1))
            continue
        match = reloc_re.match(line)
        if match and current_obj is not None:
            refs.setdefault(relocation_base(match.group(1)), set()).add(current_obj)
    return refs


def force_active_names():
    names = set()
    path = f"{BUILD}/ldscript.lcf"
    if not os.path.exists(path):
        return names
    active = False
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if stripped == "FORCEACTIVE":
                active = True
                continue
            if not active:
                continue
            if stripped == "{":
                continue
            if stripped == "}":
                break
            if stripped:
                names.add(stripped)
    return names


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


def symbol_addresses():
    addresses = {}
    address_re = re.compile(r"=\s+\.\S+:0x([0-9A-Fa-f]+);")
    for line in open(f"config/GSAE01/symbols.txt"):
        if " = " not in line:
            continue
        match = address_re.search(line)
        if match:
            addresses[line.split(" = ", 1)[0].strip()] = int(match.group(1), 16)
    return addresses


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--explain", action="store_true", help="print rejection reasons")
    args = ap.parse_args()

    report = json.load(open(f"{BUILD}/report.json"))
    resolvable = resolvable_names()
    addresses = symbol_addresses()
    referrers = relocation_referrers()
    referenced = set(referrers)
    force_active = force_active_names()

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
        ab, ao = section_alignments(built), section_alignments(orig)
        if ab != ao:
            rejected.append((sp, f"section-alignment {ab} vs {ao}"))
            continue
        if any(
            name not in BSS_SECTIONS and section_bytes(built, name) != section_bytes(orig, name)
            for name in sb
        ):
            rejected.append((sp, "section-bytes"))
            continue
        bases = section_bases(orig, addresses)
        if relocation_layout(built, addresses, bases) != relocation_layout(orig, addresses, bases):
            rejected.append((sp, "relocations"))
            continue
        built_layout = defined_symbol_layout(built, resolvable)
        orig_layout = defined_symbol_layout(orig, resolvable)
        if built_layout != orig_layout:
            changed = sorted(
                name
                for name in built_layout.keys() | orig_layout.keys()
                if built_layout.get(name) != orig_layout.get(name)
            )
            rejected.append((sp, f"symbol-layout {changed[:3]}"))
            continue
        external_names = {
            name
            for name, owners in referrers.items()
            if any(owner != os.path.abspath(orig) for owner in owners)
        }
        built_external = defined_symbol_layout(built, external_names)
        orig_external = defined_symbol_layout(orig, external_names)
        if built_external != orig_external:
            changed = sorted(
                name
                for name in built_external.keys() | orig_external.keys()
                if built_external.get(name) != orig_external.get(name)
            )
            rejected.append((sp, f"cross-object-symbol {changed[:3]}"))
            continue
        dead_bss = []
        for section in BSS_SECTIONS & sb.keys():
            owned = [name for name, entry in built_layout.items() if entry[0] == section]
            if owned and not any(
                name in referenced or name in force_active for name in owned
            ):
                dead_bss.append(section)
        if dead_bss:
            rejected.append((sp, f"unreferenced-bss {sorted(dead_bss)}"))
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
