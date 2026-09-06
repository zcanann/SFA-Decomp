"""Compare generated Tricky objects without normalizing away allocation changes.

Function bytes, relocation records, and defined allocated named-symbol layouts
are separate checks. None substitutes for objdiff against retail or the diagnostic
game link. Absolute, common, and undefined symbols are not layout comparisons.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from io import BytesIO
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


@dataclass
class ObjectSnapshot:
    digest: str
    functions: dict[str, bytes]
    sections: dict[str, tuple]
    symbols: dict[str, tuple]
    relocations: dict[str, tuple]


def read_object(path: Path) -> ObjectSnapshot:
    data = path.read_bytes()
    elf = ELFFile(BytesIO(data))
    if elf["e_type"] != "ET_REL" or elf["e_machine"] != "EM_PPC":
        raise ValueError(f"expected a PowerPC relocatable object: {path}")
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        raise ValueError(f"object has no symbol table: {path}")

    sections = {}
    for section in elf.iter_sections():
        if section["sh_flags"] & 2:
            sections[section.name] = (
                section["sh_type"], section["sh_flags"], section["sh_addralign"],
                section["sh_size"], section.data(),
            )

    functions = {}
    symbols = {}
    for symbol in symtab.iter_symbols():
        section_index = symbol["st_shndx"]
        if not symbol.name or not isinstance(section_index, int):
            continue
        section = elf.get_section(section_index)
        if not (section["sh_flags"] & 2):
            continue
        offset, size = symbol["st_value"], symbol["st_size"]
        if not symbol.name.startswith("@"):
            if symbol.name in symbols:
                raise ValueError(f"duplicate named symbol in {path}: {symbol.name}")
            symbols[symbol.name] = (
                section.name, offset, size, symbol["st_info"]["type"],
                symbol["st_info"]["bind"], symbol["st_other"]["visibility"],
            )
        if symbol["st_info"]["type"] == "STT_FUNC":
            if offset + size > section["sh_size"]:
                raise ValueError(f"function extends beyond its section in {path}: {symbol.name}")
            functions[symbol.name] = section.data()[offset:offset + size]

    relocations = {}
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        target = elf.get_section(section["sh_info"])
        if not (target["sh_flags"] & 2):
            continue
        table = elf.get_section(section["sh_link"])
        records = []
        for relocation in section.iter_relocations():
            symbol = table.get_symbol(relocation["r_info_sym"])
            symbol_section = symbol["st_shndx"]
            if isinstance(symbol_section, int):
                symbol_section = elf.get_section(symbol_section).name
            records.append((
                relocation["r_offset"], relocation["r_info_type"],
                relocation["r_addend"] if section.is_RELA() else None,
                symbol.name, symbol_section, symbol["st_value"],
            ))
        key = f"{section.name} -> {target.name}"
        relocations[key] = tuple(sorted(records))

    return ObjectSnapshot(hashlib.sha256(data).hexdigest(), functions, sections, symbols, relocations)


def byte_changes(before: bytes | None, after: bytes | None) -> dict:
    if before is None or after is None:
        return {"missing_from": "baseline" if before is None else "current"}
    return {
        "baseline_size": len(before), "current_size": len(after),
        "changed_bytes": sum(a != b for a, b in zip(before, after)) + abs(len(before) - len(after)),
    }


def without_anonymous_names(records: tuple) -> Counter:
    return Counter(
        (*record[:3], "" if record[3].startswith("@") and record[4] != "SHN_UNDEF" else record[3], *record[4:])
        for record in records
    )


def compare_objects(before: ObjectSnapshot, after: ObjectSnapshot) -> dict:
    functions = {
        name: byte_changes(before.functions.get(name), after.functions.get(name))
        for name in sorted(before.functions.keys() | after.functions.keys())
        if before.functions.get(name) != after.functions.get(name)
    }
    sections = {}
    for name in sorted(before.sections.keys() | after.sections.keys()):
        old, new = before.sections.get(name), after.sections.get(name)
        if old == new:
            continue
        sections[name] = byte_changes(None if old is None else old[-1], None if new is None else new[-1])
        sections[name]["baseline_layout"] = None if old is None else old[:-1]
        sections[name]["current_layout"] = None if new is None else new[:-1]
    symbols = {
        name: {"baseline": before.symbols.get(name), "current": after.symbols.get(name)}
        for name in sorted(before.symbols.keys() | after.symbols.keys())
        if before.symbols.get(name) != after.symbols.get(name)
    }
    relocations = {}
    for name in sorted(before.relocations.keys() | after.relocations.keys()):
        old, new = Counter(before.relocations.get(name, ())), Counter(after.relocations.get(name, ()))
        if old != new:
            old_targets = without_anonymous_names(before.relocations.get(name, ()))
            new_targets = without_anonymous_names(after.relocations.get(name, ()))
            relocations[name] = {
                "removed": list((old - new).elements()), "added": list((new - old).elements()),
                "ignoring_anonymous_names": {
                    "removed_count": sum((old_targets - new_targets).values()),
                    "added_count": sum((new_targets - old_targets).values()),
                },
            }
    return {
        "byte_identical": before.digest == after.digest,
        "baseline_sha256": before.digest, "current_sha256": after.digest,
        "function_byte_changes": functions, "allocated_section_changes": sections,
        "named_symbol_changes": symbols, "relocation_changes": relocations,
    }


def comparison_summary(result: dict) -> str:
    rows = [f"Byte-identical object: {result['byte_identical']}",
            f"Baseline SHA256: {result['baseline_sha256']}",
            f"Current SHA256:  {result['current_sha256']}"]
    for key, label in (("function_byte_changes", "Function byte changes"),
                       ("allocated_section_changes", "Allocated section changes"),
                       ("named_symbol_changes", "Named symbol changes")):
        entries = result[key]
        rows.append(f"{label}: {len(entries)}")
        for name, change in list(entries.items())[:12]:
            if "changed_bytes" in change:
                rows.append(f"  {name}: {change['changed_bytes']} differing bytes, "
                            f"size {change['baseline_size']} -> {change['current_size']}")
            elif "missing_from" in change:
                rows.append(f"  {name}: missing from {change['missing_from']}")
            else:
                rows.append(f"  {name}: {change['baseline']} -> {change['current']}")
            if "baseline_layout" in change and change["baseline_layout"] != change["current_layout"]:
                rows.append(f"    layout: {change['baseline_layout']} -> {change['current_layout']}")
        if len(entries) > 12:
            rows.append(f"  ... {len(entries) - 12} more (use --object-details)")
    rows.append(f"Relocation section changes: {len(result['relocation_changes'])}")
    for name, change in result["relocation_changes"].items():
        targets = change["ignoring_anonymous_names"]
        rows.append(f"  {name}: {len(change['removed'])} removed, {len(change['added'])} added; "
                    f"ignoring anonymous names: {targets['removed_count']} removed, {targets['added_count']} added")
    return "\n".join(rows)
