"""Inspect MWCC's Tricky local locations without changing the production build.

DWARF 1.1 encoding: https://dwarfstd.org/doc/dwarf_1_1_0.pdf, sections 2.3 and 4.
This describes the reconstructed source, not recovered retail debug information.
"""

from __future__ import annotations

import argparse
from bisect import bisect_right
from collections.abc import Set
from dataclasses import dataclass, field
from pathlib import Path
import subprocess

from elftools.elf.elffile import ELFFile

import flag_probe
import strucdiff
from compiler_command import split_command_line
from tricky_object_compare import ObjectSnapshot, read_object
from tricky_source_order_probe import compile_command


ROOT = Path(__file__).resolve().parents[1]
UNIT = "main/dlls/objects/196_Tricky/tricky"
SOURCE = ROOT / "src/dlls/objects/196_Tricky/tricky.c"
PRODUCTION = ROOT / "build/GSAE01/src/dlls/objects/196_Tricky/tricky.o"
OUTPUT = ROOT / "build/flag_probe/tricky_debug_locations"
TAG_NAMES = {
    5: "argument", 6: "function", 11: "block", 12: "local",
    20: "function", 29: "inline",
}


@dataclass
class Entry:
    offset: int
    end: int
    tag: int
    attributes: dict[int, int | str | bytes]
    unresolved: set[int] = field(default_factory=set)
    extensions: list[tuple[int, int | str | bytes]] = field(default_factory=list)

    @property
    def name(self) -> str:
        return str(self.attributes.get(0x30, ""))


def relocated_section(elf: ELFFile, name: str) -> tuple[bytes, set[int]]:
    section = elf.get_section_by_name(name)
    if section is None:
        raise ValueError(f"missing DWARF 1 {name} section")
    data = bytearray(section.data())
    unresolved = set()
    relocations = elf.get_section_by_name(".rela" + name)
    if relocations is None:
        return bytes(data), unresolved
    if relocations["sh_info"] != elf.get_section_index(name):
        raise ValueError(f"relocations do not target {name}")
    symbols = elf.get_section(relocations["sh_link"])
    for relocation in relocations.iter_relocations():
        if relocation["r_info_type"] not in (1, 24):  # ADDR32 and UADDR32
            raise ValueError(f"unsupported debug relocation: {relocation['r_info_type']}")
        symbol = symbols.get_symbol(relocation["r_info_sym"])
        offset = relocation["r_offset"]
        if not 0 <= offset <= len(data) - 4:
            raise ValueError("debug relocation outside section")
        if symbol["st_shndx"] == "SHN_UNDEF":
            unresolved.add(offset)
            continue
        if not isinstance(symbol["st_shndx"], int) and symbol["st_shndx"] != "SHN_ABS":
            raise ValueError(f"unsupported debug relocation symbol: {symbol.name}")
        value = symbol["st_value"] + relocation["r_addend"]
        data[offset:offset + 4] = value.to_bytes(4, "big")
    return bytes(data), unresolved


def parse_entries(data: bytes, unresolved: Set[int] = frozenset()) -> list[Entry]:
    entries = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            if any(data[offset:]):
                raise ValueError(f"nonzero trailing debug bytes at {offset:#x}")
            break
        size = int.from_bytes(data[offset:offset + 4], "big")
        if size == 0:
            if any(data[offset:]):
                raise ValueError(f"zero-sized debug entry at {offset:#x}")
            break
        end = offset + size
        if size < 4 or end > len(data):
            raise ValueError(f"invalid debug entry size at {offset:#x}")
        if size < 8:
            entries.append(Entry(offset, end, 0, {}))
            offset = end
            continue
        tag = int.from_bytes(data[offset + 4:offset + 6], "big")
        cursor = offset + 6
        attributes = {}
        unresolved_attributes = set()
        extensions = []

        def take(length: int) -> bytes:
            nonlocal cursor
            if cursor + length > end:
                raise ValueError(f"attribute outside debug entry at {offset:#x}")
            result = data[cursor:cursor + length]
            cursor += length
            return result

        while tag != 0 and cursor < end:
            attribute = int.from_bytes(take(2), "big")
            value_start = cursor
            form = attribute & 15
            if form in (1, 2, 5, 6, 7):
                width = {1: 4, 2: 4, 5: 2, 6: 4, 7: 8}[form]
                value = int.from_bytes(take(width), "big")
            elif form in (3, 4):
                length = int.from_bytes(take(2 if form == 3 else 4), "big")
                value = take(length)
            elif form == 8:
                terminator = data.find(b"\0", cursor, end)
                if terminator < 0:
                    raise ValueError(f"unterminated debug string at {cursor:#x}")
                value = take(terminator - cursor + 1)[:-1].decode("latin-1")
            else:
                raise ValueError(f"unsupported attribute form {form:#x} at {cursor - 2:#x}")
            key = attribute & ~15
            if 0x2000 <= key <= 0x3FF0:
                extensions.append((attribute, value))
            else:
                if key in attributes:
                    raise ValueError(f"duplicate attribute {key:#x} at {offset:#x}")
                attributes[key] = value
            if any(value_start <= address < cursor for address in unresolved):
                unresolved_attributes.add(key)
        entries.append(Entry(offset, end, tag, attributes, unresolved_attributes, extensions))
        offset = end
    return entries


def location(expression: bytes) -> str:
    if not expression:
        return "optimized out"
    cursor = 0
    atoms = []
    while cursor < len(expression):
        opcode = expression[cursor]
        cursor += 1
        if opcode in (1, 2, 3, 4):
            if cursor + 4 > len(expression):
                raise ValueError("truncated location operand")
            value = int.from_bytes(expression[cursor:cursor + 4], "big", signed=opcode == 4)
            cursor += 4
            name = {1: "reg", 2: "base", 3: "addr", 4: "const"}[opcode]
            atoms.append(f"{name}({value})")
        elif opcode in (5, 6, 7):
            atoms.append({5: "deref2", 6: "deref", 7: "add"}[opcode])
        else:
            return f"opaque location {expression.hex()}"
    return " ".join(atoms)


def function_entries(entries: list[Entry], name: str) -> list[tuple[int, Entry]]:
    matches = [entry for entry in entries if entry.tag in (6, 20) and entry.name == name]
    if len(matches) != 1:
        raise ValueError(f"expected one function named {name}, found {len(matches)}")
    root = matches[0]
    limit = root.attributes.get(0x10)
    if not isinstance(limit, int) or not root.end <= limit <= entries[-1].end:
        raise ValueError(f"invalid sibling for {name}")
    if 0x10 in root.unresolved:
        raise ValueError(f"unresolved sibling for {name}")
    stack = []
    result = []
    for entry in entries:
        if not root.offset <= entry.offset < limit:
            continue
        while stack and entry.offset >= stack[-1]:
            stack.pop()
        result.append((len(stack), entry))
        sibling = entry.attributes.get(0x10)
        if isinstance(sibling, int) and sibling > entry.end:
            if sibling > (stack[-1] if stack else limit):
                raise ValueError(f"scope extends beyond its parent at {entry.offset:#x}")
            stack.append(sibling)
    return result


def parse_lines(data: bytes) -> list[tuple[int, int]]:
    """Return section-relative addresses and source lines, preserving end markers."""
    lines = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise ValueError("truncated line table header")
        size = int.from_bytes(data[offset:offset + 4], "big")
        base = int.from_bytes(data[offset + 4:offset + 8], "big")
        end = offset + size
        if size < 18 or end > len(data) or (size - 8) % 10:
            raise ValueError("invalid line table size")
        for cursor in range(offset + 8, end, 10):
            number = int.from_bytes(data[cursor:cursor + 4], "big")
            delta = int.from_bytes(data[cursor + 6:cursor + 10], "big")
            # MWCC also emits interior zero-line markers; do not extend the preceding line across them.
            lines.append((base + delta, number))
        if lines[-1][1] != 0:
            raise ValueError("missing line table end marker")
        offset = end
    return sorted(lines, key=lambda row: row[0])


def source_line(lines: list[tuple[int, int]], address: int) -> int | None:
    index = bisect_right(lines, address, key=lambda row: row[0]) - 1
    return (lines[index][1] or None) if index >= 0 else None


def differences(obj: Path, entries: list[Entry], lines: list[tuple[int, int]], name: str) -> None:
    _, function = function_entries(entries, name)[0]
    base = function.attributes[0x110]
    if function.unresolved & {0x110, 0x120}:
        raise ValueError(f"unresolved function address for {name}")
    rows, target, current, _, count = strucdiff.analyse(UNIT, name, str(obj))
    if function.attributes[0x120] - base != count * 4:
        raise ValueError(f"debug range does not cover disassembled function {name}")
    for kind, target_index, current_index in rows:
        if kind == " ":
            continue
        number = source_line(lines, base + current_index * 4) if current_index is not None else None
        before = target[target_index] if target_index is not None else "(absent)"
        after = current[current_index] if current_index is not None else "(absent)"
        print(f"{name}[{target_index}/{current_index}] line {number}: {before} | {after}")


def require_production_equivalence(before: ObjectSnapshot, after: ObjectSnapshot) -> None:
    for field in ("functions", "sections", "symbols", "relocations"):
        if getattr(before, field) != getattr(after, field):
            raise ValueError(f"debug compilation changed {field}; cannot use as production allocation evidence")


def build() -> Path:
    subprocess.run(["ninja", str(PRODUCTION.relative_to(ROOT))], cwd=ROOT, check=True, timeout=30)
    before = read_object(PRODUCTION)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    command = compile_command(split_command_line(flag_probe.base_cmd(UNIT)), SOURCE, OUTPUT)
    subprocess.run(command + ["-sym", "on"], cwd=ROOT, check=True, timeout=30)
    obj = OUTPUT / "tricky.o"
    after = read_object(obj)
    require_production_equivalence(before, after)
    print("Debug compilation preserves all production function/section bytes, layouts, and relocations.")
    return obj


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("functions", nargs="*", default=["moveTricky", "trickyUpdateMovementState",
                                                        "Tricky_updateSideCommandPrompts"])
    parser.add_argument("--object", type=Path, help="Inspect an existing debug object; skips the production-equivalence gate")
    parser.add_argument("--differences", action="store_true", help="Map retail instruction mismatches to MWCC source lines")
    args = parser.parse_args()
    obj = args.object or build()
    if args.object:
        print("Existing object: production equivalence has not been checked.")
    with obj.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or elf.little_endian or elf["e_machine"] != "EM_PPC" or elf["e_type"] != "ET_REL":
            raise ValueError("expected a big-endian 32-bit PowerPC relocatable object")
        entries = parse_entries(*relocated_section(elf, ".debug"))
        if args.differences:
            line_data, unresolved = relocated_section(elf, ".line")
            if unresolved:
                raise ValueError("unresolved line table address")
            lines = parse_lines(line_data)
    print("PC values are object-section offsets; lexical scopes are not live ranges.")
    print("Optimized debug locations are advisory, not a proof of register liveness.")
    for name in args.functions:
        if args.differences:
            differences(obj, entries, lines, name)
            continue
        for depth, entry in function_entries(entries, name):
            if entry.tag not in TAG_NAMES:
                continue
            if entry.unresolved & {0x10, 0x20, 0x110, 0x120}:
                raise ValueError(f"unresolved location/scope relocation for {entry.name}")
            details = []
            for key, label in ((0x110, "low"), (0x120, "high")):
                if key in entry.attributes:
                    details.append(f"{label}={entry.attributes[key]:#x}")
            if 0x20 in entry.attributes:
                details.append(location(entry.attributes[0x20]))
            print(f"{'  ' * depth}{TAG_NAMES[entry.tag]} {entry.name}: {'; '.join(details)}")


if __name__ == "__main__":
    main()
