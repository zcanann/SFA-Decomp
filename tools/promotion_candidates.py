#!/usr/bin/env python3
"""Find report-complete objects whose raw ELF layouts are promotion candidates.

Objdiff's 100% score compares section contents, but a source object can still
carry an extra constant pool or reference a different symbol at an otherwise
identical instruction.  This audit compares alloc-section layout and resolved
relocations before suggesting a NonMatching object for a trial link.  The final
link and checksum remain authoritative because another object may consume a
target data label that the compiler kept local in the source object.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


SECTION_RE = re.compile(
    r"^\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+"
    r"[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+2\*\*(\d+)"
)
RELOC_SECTION_RE = re.compile(r"^RELOCATION RECORDS FOR \[(.+)\]:$")
RELOC_RE = re.compile(r"^([0-9a-fA-F]+)\s+(R_PPC_\S+)\s+(.+?)\s*$")
IGNORED_SECTIONS = {".comment", ".note.split"}


@dataclass(frozen=True)
class ElfContract:
    sections: tuple[tuple[str, int, int], ...]
    relocations: tuple[tuple[str, int, str, str], ...]
    exports: tuple[str, ...]


def run_objdump(objdump: Path, option: str, path: Path) -> str:
    result = subprocess.run(
        [str(objdump), option, str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def read_contract(objdump: Path, path: Path) -> ElfContract:
    sections = []
    for line in run_objdump(objdump, "-h", path).splitlines():
        match = SECTION_RE.match(line)
        if match and match.group(1) not in IGNORED_SECTIONS:
            sections.append(
                (match.group(1), int(match.group(2), 16), int(match.group(3)))
            )

    symbols = {}
    exports = []
    for line in run_objdump(objdump, "-t", path).splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[1] in {"l", "g", "w"}:
            symbols[fields[5]] = (fields[3], int(fields[0], 16))
            if fields[1] in {"g", "w"}:
                exports.append(fields[5])

    relocations = []
    reloc_section = ""
    for line in run_objdump(objdump, "-r", path).splitlines():
        section_match = RELOC_SECTION_RE.match(line)
        if section_match:
            reloc_section = section_match.group(1)
            continue
        reloc_match = RELOC_RE.match(line)
        if reloc_match:
            target = reloc_match.group(3)
            symbol, separator, addend_text = target.partition("+")
            if symbol in symbols:
                section, value = symbols[symbol]
                addend = int(addend_text, 0) if separator else 0
                target = f"{section}+0x{value + addend:x}"
            relocations.append(
                (
                    reloc_section,
                    int(reloc_match.group(1), 16),
                    reloc_match.group(2),
                    target,
                )
            )

    return ElfContract(tuple(sections), tuple(relocations), tuple(exports))


def read_linker_undefined_symbols(objdump: Path, build: Path) -> set[str]:
    inputs = subprocess.run(
        ["ninja", "-t", "inputs", str(build / "main.elf")],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    objects = [Path(line.strip()) for line in inputs if line.strip().endswith(".o")]
    undefined = set()
    for start in range(0, len(objects), 32):
        command = [str(objdump), "-t", *(str(path) for path in objects[start : start + 32])]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[1] == "*UND*":
                undefined.add(fields[3])
    return undefined


def is_report_exact(unit: dict) -> bool:
    measures = unit.get("measures", {})
    return (
        float(measures.get("matched_code_percent", 100.0)) == 100.0
        and float(measures.get("matched_data_percent", 100.0)) == 100.0
        and not unit.get("metadata", {}).get("complete", False)
        and not unit.get("metadata", {}).get("auto_generated", False)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="GSAE01")
    parser.add_argument("--show-rejected", action="store_true")
    args = parser.parse_args()

    build = Path("build") / args.version
    report_path = build / "report.json"
    objdump = Path("build/binutils/powerpc-eabi-objdump.exe")
    if not objdump.exists():
        objdump = Path("build/binutils/powerpc-eabi-objdump")
    if not report_path.exists() or not objdump.exists():
        parser.error("run configure.py and ninja first so report.json and binutils exist")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    linker_undefined = read_linker_undefined_symbols(objdump, build)
    ready = []
    rejected = []
    for unit in report["units"]:
        if not is_report_exact(unit):
            continue
        name = unit["name"]
        if "/" not in name:
            continue
        object_path = name.split("/", 1)[1]
        target = build / "obj" / f"{object_path}.o"
        source = build / "src" / f"{object_path}.o"
        if not target.exists() or not source.exists():
            continue

        target_contract = read_contract(objdump, target)
        source_contract = read_contract(objdump, source)
        target_exports = set(target_contract.exports)
        source_exports = set(source_contract.exports)
        missing_consumed_exports = sorted(
            (target_exports & linker_undefined) - source_exports
        )
        same_layout = target_contract.sections == source_contract.sections
        same_relocations = target_contract.relocations == source_contract.relocations
        if same_layout and same_relocations and not missing_consumed_exports:
            ready.append((name, int(unit.get("measures", {}).get("total_code", 0))))
            continue

        reasons = []
        if not same_layout:
            reasons.append("sections")
        if not same_relocations:
            reasons.append("relocations")
        if missing_consumed_exports:
            reasons.append("external-consumers")
        rejected.append((name, ",".join(reasons)))

    ready.sort(key=lambda item: (-item[1], item[0]))
    print(f"structural promotion candidates: {len(ready)}")
    for name, code_size in ready:
        print(f"{code_size:7d}  {name}")
    if args.show_rejected:
        print(f"\nrejected despite 100% report: {len(rejected)}")
        for name, reasons in rejected:
            print(f"{reasons:28s}  {name}")


if __name__ == "__main__":
    main()
