#!/usr/bin/env python3
"""Compare emitted function sizes against retail, per unit or tree-wide.

A function whose emitted size differs from retail's can never byte-match, no
matter what fuzzy_match_percent reports. Ours being LARGER is the worse case:
it means a source change bought fuzzy points by adding instructions.

Usage:
  python3 tools/size_parity_check.py                      # tree-wide
  python3 tools/size_parity_check.py <unit-substring> ...  # selected units
  python3 tools/size_parity_check.py --larger-only
  python3 tools/size_parity_check.py --json
"""

import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDIFF_JSON = os.path.join(ROOT, "objdiff.json")

STT_FUNC = 2


def _read_elf_func_sizes(path):
    """Return {symbol_name: size} for STT_FUNC symbols in executable sections.

    Returns None if the file is missing or not a big-endian ELF32 we understand.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    if data[4] != 1 or data[5] != 2:  # ELFCLASS32, ELFDATA2MSB
        return None

    e_shoff, = struct.unpack_from(">I", data, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(">HHH", data, 0x2E)
    if e_shoff == 0 or e_shnum == 0:
        return None

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
            ">IIIIIIIIII", data, off)
        sections.append({
            "name_off": sh_name, "type": sh_type, "flags": sh_flags,
            "offset": sh_offset, "size": sh_size, "link": sh_link,
            "entsize": sh_entsize,
        })

    shstr = sections[e_shstrndx]

    def sec_name(sec):
        base = shstr["offset"] + sec["name_off"]
        end = data.index(b"\0", base)
        return data[base:end].decode("ascii", "replace")

    symtab = None
    for sec in sections:
        if sec["type"] == 2 and sec_name(sec) == ".symtab":  # SHT_SYMTAB
            symtab = sec
            break
    if symtab is None:
        return None
    strtab = sections[symtab["link"]]

    def str_at(off):
        base = strtab["offset"] + off
        end = data.index(b"\0", base)
        return data[base:end].decode("ascii", "replace")

    out = {}
    entsize = symtab["entsize"] or 16
    count = symtab["size"] // entsize
    for i in range(count):
        off = symtab["offset"] + i * entsize
        st_name, st_value, st_size, st_info, st_other, st_shndx = \
            struct.unpack_from(">IIIBBH", data, off)
        if (st_info & 0xF) != STT_FUNC:
            continue
        if st_shndx == 0 or st_shndx >= len(sections):
            continue
        name = str_at(st_name)
        if not name:
            continue
        # Last definition wins; duplicates are not expected within one object.
        out[name] = st_size
    return out


def load_units():
    with open(OBJDIFF_JSON) as fh:
        cfg = json.load(fh)
    return cfg["units"]


def check_unit(unit):
    """Return (status, rows). rows = [(name, ours, retail)] for mismatches."""
    target = unit.get("target_path")
    base = unit.get("base_path")
    if not target or not base:
        return "no-paths", []
    tpath = os.path.join(ROOT, target)
    bpath = os.path.join(ROOT, base)
    if not os.path.exists(tpath):
        return "no-target", []
    if not os.path.exists(bpath):
        return "not-built", []
    tsyms = _read_elf_func_sizes(tpath)
    bsyms = _read_elf_func_sizes(bpath)
    if tsyms is None or bsyms is None:
        return "unreadable", []
    rows = []
    for name, tsize in sorted(tsyms.items()):
        if name not in bsyms:
            continue  # unpaired; a different defect class
        osize = bsyms[name]
        if osize != tsize:
            rows.append((name, osize, tsize))
    return "ok", rows


def main(argv):
    larger_only = "--larger-only" in argv
    as_json = "--json" in argv
    filters = [a for a in argv if not a.startswith("--")]

    units = load_units()
    if filters:
        units = [u for u in units
                 if any(f in u.get("name", "") for f in filters)]
        if not units:
            print("no units matched %r" % (filters,), file=sys.stderr)
            return 2

    results = []
    stats = {}
    checked_fns = 0
    for unit in units:
        status, rows = check_unit(unit)
        stats[status] = stats.get(status, 0) + 1
        if status != "ok":
            continue
        # count paired functions actually compared
        tpath = os.path.join(ROOT, unit["target_path"])
        bpath = os.path.join(ROOT, unit["base_path"])
        ts = _read_elf_func_sizes(tpath) or {}
        bs = _read_elf_func_sizes(bpath) or {}
        checked_fns += len(set(ts) & set(bs))
        for name, osize, tsize in rows:
            if larger_only and osize <= tsize:
                continue
            results.append({
                "unit": unit["name"], "function": name,
                "ours": osize, "retail": tsize, "delta": osize - tsize,
            })

    if as_json:
        print(json.dumps(results, indent=1))
    else:
        bigger = [r for r in results if r["delta"] > 0]
        smaller = [r for r in results if r["delta"] < 0]
        for label, group in (("OURS LARGER", bigger), ("ours smaller", smaller)):
            if not group:
                continue
            print("=== %s (%d) ===" % (label, len(group)))
            for r in sorted(group, key=lambda x: -abs(x["delta"])):
                print("  %-44s %-34s ours=0x%-6x retail=0x%-6x %+d" % (
                    r["unit"], r["function"], r["ours"], r["retail"],
                    r["delta"]))
        print()
        print("units: %s" % ", ".join(
            "%s=%d" % kv for kv in sorted(stats.items())))
        print("paired functions compared: %d" % checked_fns)
        print("size mismatches: %d (larger %d, smaller %d)" % (
            len(results), len(bigger), len(smaller)))

    return 1 if any(r["delta"] > 0 for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
