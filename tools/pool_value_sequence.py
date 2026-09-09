"""Compare what our code ASKS the literal pool for against what retail's does.

For each function, walk `.text` in address order and record the bytes of every
SDA21 load at its actual width. Do it for our object and for the
retail split object, and compare the two sequences.

Equal sequences mean the two objects load the same constants in the same order.
Repeated loads are retained unless --collapse-repeats is explicitly requested.
This does not prove section equality: unused data, placement, padding and other
relocation kinds still need auditing. Non-load SDA21 references are reported as
unscannable rather than guessed to consume one word.

A differing sequence identifies a load/value/reference difference within the
selected sections. Use --sections when a value may have moved between pools.

Usage:
  python3 tools/pool_value_sequence.py <src-path> [section]
  python3 tools/pool_value_sequence.py --all [section]
  python3 tools/pool_value_sequence.py src/main/trig.c --version GSAJ01
  python3 tools/pool_value_sequence.py <src-path> --sections .sdata,.sdata2

Exit status: 0 if every function's sequence matches, 1 otherwise.
"""
from __future__ import annotations

from bisect import bisect_right
import argparse
import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_PPC
from version_progress import verified_dol

REPO = Path(__file__).resolve().parent.parent
VERSION = "GSAE01"
LOAD_WIDTHS = {
    32: 4, 33: 4,  # lwz, lwzu
    34: 1, 35: 1,  # lbz, lbzu
    40: 2, 41: 2,  # lhz, lhzu
    42: 2, 43: 2,  # lha, lhau
    48: 4, 49: 4,  # lfs, lfsu
    50: 8, 51: 8,  # lfd, lfdu
}


class UnscannableObject(Exception):
    """The object cannot be checked with the supported literal-load model."""


class MissingObject(UnscannableObject):
    """A row's object pair is absent -- the row is unscannable, not clean."""


def sequences(obj: Path, section: str | tuple[str, ...], *, collapse_repeats: bool = False
              ) -> tuple[dict[str, list[str]], list[str]]:
    """{function: [loaded bytes, ...]} and function order, read from ELF records."""
    with obj.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or elf.little_endian or elf["e_machine"] != "EM_PPC":
            raise UnscannableObject(f"expected a big-endian ELF32 PowerPC object: {obj}")
        symbols = elf.get_section_by_name(".symtab")
        text_index = elf.get_section_index(".text")
        if symbols is None or text_index is None:
            raise UnscannableObject(f"missing text/symbol table: {obj}")
        functions = sorted(
            (symbol["st_value"], symbol.name, symbol["st_size"])
            for symbol in symbols.iter_symbols()
            if symbol["st_shndx"] == text_index and symbol["st_info"]["type"] == "STT_FUNC"
        )
        order = [name for _, name, _ in functions]
        seqs: dict[str, list[str]] = {name: [] for name in order}
        sections = (section,) if isinstance(section, str) else section
        pools = {
            index: (name, elf.get_section(index).data())
            for name in sections
            if (index := elf.get_section_index(name)) is not None
        }
        relocations = elf.get_section_by_name(".rela.text")
        if elf.get_section_by_name(".rel.text") is not None:
            raise UnscannableObject(f"REL text relocations are not supported: {obj}")
        if not pools or relocations is None:
            return seqs, order
        text = elf.get_section(text_index).data()
        starts = [start for start, _, _ in functions]
        for reloc in sorted(relocations.iter_relocations(), key=lambda r: r["r_offset"]):
            if reloc["r_info_type"] != ENUM_RELOC_TYPE_PPC["R_PPC_EMB_SDA21"]:
                continue
            symbol = symbols.get_symbol(reloc["r_info_sym"])
            if symbol["st_shndx"] not in pools:
                continue
            section_name, blob = pools[symbol["st_shndx"]]
            address = reloc["r_offset"]
            instruction = text[address:address + 4]
            index = bisect_right(starts, address) - 1
            if len(instruction) != 4 or index < 0:
                raise UnscannableObject(f"invalid SDA21 location {address:#x}: {obj}")
            start, name, size = functions[index]
            if address >= start + size:
                raise UnscannableObject(f"SDA21 outside function at {address:#x}: {obj}")
            opcode = int.from_bytes(instruction, "big") >> 26
            width = LOAD_WIDTHS.get(opcode)
            if width is None:
                raise UnscannableObject(f"non-load SDA21 opcode {opcode} in {name}: {obj}")
            offset = symbol["st_value"] + reloc["r_addend"]
            if offset < 0 or offset + width > len(blob):
                raise UnscannableObject(f"{width}-byte load outside {section_name} in {name}: {obj}")
            value = blob[offset:offset + width].hex()
            if not collapse_repeats or not seqs[name] or seqs[name][-1] != value:
                seqs[name].append(value)
        return seqs, order


def compare(src_rel: str, section: str | tuple[str, ...], quiet: bool = False, *,
            version: str = VERSION, collapse_repeats: bool = False) -> tuple[int, int]:
    stem = src_rel[:-2] if src_rel.endswith(".c") else src_rel
    ours = REPO / "build" / version / (stem + ".o")
    retail = REPO / "build" / version / ("obj" + stem[3:] + ".o")
    if not (ours.is_file() and retail.is_file()):
        raise MissingObject(f"missing object for {src_rel}")
    ours_seqs, ours_order = sequences(ours, section, collapse_repeats=collapse_repeats)
    retail_seqs, retail_order = sequences(retail, section, collapse_repeats=collapse_repeats)
    same = diff = 0
    for fn in retail_order + [name for name in ours_order if name not in retail_seqs]:
        a = ours_seqs.get(fn, [])
        b = retail_seqs.get(fn, [])
        if not a and not b:
            continue
        if a == b:
            same += 1
            continue
        diff += 1
        if not quiet:
            print("DIFF %-40s n=%d/%d" % (fn, len(a), len(b)))
            print("      ours  ", " ".join(a))
            print("      retail", " ".join(b))
    return same, diff


def sub100_sections(version: str = VERSION) -> list[tuple[str, str, float, int]]:
    report = json.loads((REPO / "build" / version / "report.json").read_text())
    rows = []
    for unit in report["units"]:
        src = unit.get("metadata", {}).get("source_path")
        if not src or not src.startswith("src/"):
            continue
        for sec in unit.get("sections", []):
            if sec["name"] == ".text":
                continue
            score = sec.get("fuzzy_match_percent", 0.0)
            size = int(sec.get("size", 0))
            if score < 100.0 and size:
                rows.append((src, sec["name"], score, size))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", nargs="?", help="source path, or section filter with --all")
    parser.add_argument("section", nargs="?", help="pool section (default: .sdata2)")
    parser.add_argument("--all", action="store_true", help="scan sub-100 data sections in the version's report")
    parser.add_argument("-v", "--version", default=VERSION,
                        choices=sorted(path.parent.name for path in (REPO / "config").glob("*/config.yml")))
    parser.add_argument("--sections", help="comma-separated pools to scan together, in instruction order")
    parser.add_argument("--collapse-repeats", action="store_true",
                        help="compare consecutive distinct values instead of every load (legacy behavior)")
    args = parser.parse_args(argv)
    if args.all:
        if args.section or args.sections is not None:
            parser.error("--all accepts one optional section filter; --sections requires a source path")
    elif not args.source:
        parser.error("provide a source path or --all")
    if args.sections is not None and args.section:
        parser.error("use either a positional section or --sections")
    selected = tuple(args.sections.split(",")) if args.sections is not None else args.section or ".sdata2"
    if args.sections is not None and any(len(name) < 2 or not name.startswith(".") or name.strip() != name
                                         for name in selected):
        parser.error("--sections requires comma-separated ELF section names such as .sdata,.sdata2")
    try:
        verified_dol(REPO / "orig" / args.version / "sys/main.dol",
                     REPO / "config" / args.version / "config.yml")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")
    print(f"version {args.version}; repeated loads " + ("collapsed" if args.collapse_repeats else "retained"))
    if args.all:
        section = args.source
        bad = 0
        scanned = 0
        errors = []
        rows = [row for row in sub100_sections(args.version) if not section or row[1] == section]
        for src, sec, score, size in rows:
            try:
                same, diff = compare(src, sec, quiet=True, version=args.version,
                                     collapse_repeats=args.collapse_repeats)
            except UnscannableObject as exc:
                errors.append(str(exc))
                print("%-50s %-11s %7.3f %6dB  UNSCANNED  %s" % (src, sec, score, size, exc))
                continue
            scanned += 1
            bad += 1 if diff else 0
            print("%-50s %-11s %7.3f %6dB  SAME %2d  DIFF %2d" % (src, sec, score, size, same, diff))
        print("population %d  scanned %d  differing %d  unscanned %d"
              % (len(rows), scanned, bad, len(errors)))
        return 1 if bad or errors else 0
    try:
        same, diff = compare(args.source, selected, version=args.version,
                             collapse_repeats=args.collapse_repeats)
    except UnscannableObject as exc:
        raise SystemExit(str(exc))
    print("value-sequence SAME %d  DIFF %d" % (same, diff))
    return 1 if diff else 0


if __name__ == "__main__":
    sys.exit(main())
