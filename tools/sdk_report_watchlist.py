#!/usr/bin/env python3
"""Summarize high-signal SDK candidates from build/GSAE01/report.json."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


def get_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Show exact-report SDK files that are still unlinked, plus top near-miss SDK files."
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("build/GSAE01/report.json"),
        help="Path to the progress report JSON.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of near-miss files to print.",
    )
    parser.add_argument(
        "--probe-exact",
        action="store_true",
        help="Run sdk_import_probe.py for exact-report SDK files that are still not linked.",
    )
    parser.add_argument(
        "--probe-near",
        action="store_true",
        help="Run sdk_import_probe.py for near-miss SDK files and summarize split/boundary drift clues.",
    )
    parser.add_argument(
        "--splits",
        type=Path,
        default=Path("config/GSAE01/splits.txt"),
        help="Path to the splits file used for adjacent-file boundary hints.",
    )
    return parser


@dataclass
class ProbeSummary:
    sections: list[str]
    best_cluster: str
    assigned_split: str
    best_exact_hypothesis: str
    likely_boundary_drift: bool
    leading_functions: list[str]
    trailing_functions: list[str]
    crossing_functions: list[str]
    assigned_range: tuple[int, int] | None
    best_exact_range: tuple[int, int] | None


@dataclass
class SplitEntry:
    name: str
    start: int
    end: int


@dataclass
class ObjectLinkHints:
    exported_data_symbols: dict[str, list[str]]
    local_data_symbols: dict[str, list[str]]
    undefined_symbols: list[str]
    owner_hints: list[str]


def is_sdk(unit: dict) -> bool:
    return "sdk" in unit.get("metadata", {}).get("progress_categories", [])


def format_misses(unit: dict) -> str:
    misses = [
        f"{fn['name']}={fn.get('fuzzy_match_percent', 100.0):.3f}"
        for fn in unit.get("functions", [])
        if fn.get("fuzzy_match_percent", 100.0) != 100.0
    ]
    return ", ".join(misses[:5])


def unit_name_to_source_path(unit_name: str) -> Path | None:
    if not unit_name.startswith("main/"):
        return None

    base = Path("src") / unit_name.removeprefix("main/")
    for candidate in (base.with_suffix(".c"), base.with_suffix(".s"), base):
        if candidate.exists():
            return candidate
    return None


def parse_range(text: str) -> tuple[int, int] | None:
    match = re.search(r"(0x[0-9A-Fa-f]+)-(0x[0-9A-Fa-f]+)", text)
    if not match:
        return None
    return int(match.group(1), 16), int(match.group(2), 16)


def unit_name_to_object_path(unit_name: str) -> Path | None:
    if not unit_name.startswith("main/"):
        return None

    base = Path("build/GSAE01/src") / unit_name.removeprefix("main/")
    candidate = base.with_suffix(".o")
    return candidate if candidate.exists() else None


def load_text_splits(splits_path: Path) -> list[SplitEntry]:
    entries: list[SplitEntry] = []
    current_name: str | None = None

    for raw_line in splits_path.read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.endswith(":"):
            current_name = line[:-1]
            continue
        if current_name is None:
            continue

        match = re.match(
            r"\.text\s+start:(0x[0-9A-Fa-f]+)\s+end:(0x[0-9A-Fa-f]+)",
            line,
        )
        if match:
            entries.append(
                SplitEntry(
                    name=current_name,
                    start=int(match.group(1), 16),
                    end=int(match.group(2), 16),
                )
            )
    return entries


def source_path_to_split_name(source_path: Path) -> str:
    return source_path.relative_to("src").as_posix()


def find_adjacent_split_names(source_path: Path, split_entries: list[SplitEntry]) -> tuple[str | None, str | None]:
    split_name = source_path_to_split_name(source_path)
    for index, entry in enumerate(split_entries):
        if entry.name != split_name:
            continue
        previous_name = split_entries[index - 1].name if index > 0 else None
        next_name = split_entries[index + 1].name if index + 1 < len(split_entries) else None
        return previous_name, next_name
    return None, None


def load_symbol_owners(map_path: Path) -> tuple[dict[str, str], dict[int, str]]:
    owners: dict[str, str] = {}
    address_owners: dict[int, str] = {}
    pattern = re.compile(r"\]\s+(\S+)\s+\(object,global\)\s+found in\s+(\S+)")
    address_pattern = re.compile(
        r"^\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]{8})\s+\d+\s+(\S+)\s+(\S+\.o)\s*$"
    )

    for line in map_path.read_text(errors="replace").splitlines():
        match = pattern.search(line)
        if match:
            owners.setdefault(match.group(1), match.group(2))
        address_match = address_pattern.match(line)
        if address_match:
            address_owners.setdefault(int(address_match.group(1), 16), address_match.group(3))
    return owners, address_owners


def load_symbol_addresses(symbols_path: Path) -> dict[str, int]:
    addresses: dict[str, int] = {}
    pattern = re.compile(r"^(\S+)\s+=\s+\.\S+:(0x[0-9A-Fa-f]+);")

    for line in symbols_path.read_text(errors="replace").splitlines():
        match = pattern.match(line)
        if match:
            addresses[match.group(1)] = int(match.group(2), 16)
    return addresses


def collect_object_link_hints(
    object_path: Path,
    symbol_owners: dict[str, str],
    address_owners: dict[int, str],
    symbol_addresses: dict[str, int],
) -> ObjectLinkHints | str:
    try:
        nm_result = subprocess.run(
            ["build/binutils/powerpc-eabi-nm.exe", "-n", str(object_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        objdump_result = subprocess.run(
            ["build/binutils/powerpc-eabi-objdump.exe", "-t", str(object_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        return f"object inspection failed ({exc.returncode})"

    exported_data_symbols: dict[str, list[str]] = {}
    local_data_symbols: dict[str, list[str]] = {}
    undefined_symbols: list[str] = []
    data_sections = {".data", ".rodata", ".sdata", ".sdata2", ".bss", ".sbss"}

    for line in nm_result.stdout.splitlines():
        match = re.match(r"\s*(\S+)?\s+([A-Za-z])\s+(\S+)$", line)
        if not match:
            continue
        symbol_type = match.group(2)
        name = match.group(3)
        if symbol_type == "U":
            undefined_symbols.append(name)

    for line in objdump_result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 6:
            continue
        _, bind, symbol_kind, section, _, name = parts
        if symbol_kind != "O" or section not in data_sections:
            continue
        if bind == "g":
            exported_data_symbols.setdefault(section, []).append(name)
        elif bind == "l":
            local_data_symbols.setdefault(section, []).append(name)

    owner_hints = []
    for names in exported_data_symbols.values():
        for name in names:
            owner = symbol_owners.get(name)
            if owner is None:
                address = symbol_addresses.get(name)
                if address is not None:
                    owner = address_owners.get(address)
            if owner and owner.startswith("auto_"):
                owner_hints.append(f"{name}->{owner}")

    return ObjectLinkHints(
        exported_data_symbols=exported_data_symbols,
        local_data_symbols=local_data_symbols,
        undefined_symbols=undefined_symbols,
        owner_hints=owner_hints,
    )


def parse_probe(source_path: Path, *, include_functions: bool = False) -> ProbeSummary | str:
    command = [sys.executable, "tools/sdk_import_probe.py", str(source_path), "--show-assigned"]
    if include_functions:
        command.extend(["--show-functions", "--function-limit", "40"])

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        return f"probe failed ({exc.returncode})"

    sections: list[str] = []
    best_cluster = ""
    assigned_split = ""
    best_exact_hypothesis = ""
    likely_boundary_drift = False
    leading_functions: list[str] = []
    trailing_functions: list[str] = []
    crossing_functions: list[str] = []
    in_sections = False
    in_assigned_split = False
    in_start_hypotheses = False
    in_anchor_details = False
    in_projected_functions = False
    best_hypothesis_locked = False
    assigned_range: tuple[int, int] | None = None
    best_exact_range: tuple[int, int] | None = None
    projected_function_rows: list[tuple[int, int, str]] = []

    for line in result.stdout.splitlines():
        if line.startswith("sections:"):
            in_sections = True
            continue
        if line.startswith("assigned split:"):
            in_assigned_split = True
            in_start_hypotheses = False
            in_anchor_details = False
            in_projected_functions = False
            continue
        if line.startswith("start hypotheses:"):
            in_start_hypotheses = True
            in_assigned_split = False
            in_anchor_details = False
            in_projected_functions = False
            continue
        if line.startswith("  anchor details:"):
            in_anchor_details = True
            in_projected_functions = False
            continue
        if line.startswith("  projected functions:") and best_exact_hypothesis and not best_hypothesis_locked:
            in_projected_functions = True
            in_anchor_details = False
            continue
        if line.startswith("  0x") and best_exact_hypothesis:
            best_hypothesis_locked = True
            in_anchor_details = False
            in_projected_functions = False
        if in_sections:
            if not line.startswith("  ."):
                in_sections = False
            else:
                section_match = re.match(r"\s+(\.\S+)\s+(0x[0-9A-Fa-f]+)", line)
                if section_match:
                    sections.append(f"{section_match.group(1)}={section_match.group(2)}")
                continue
        if in_assigned_split and not assigned_split:
            assigned_match = re.match(
                r"\s+(0x[0-9A-Fa-f]+-0x[0-9A-Fa-f]+.*?delta=[+-]0x[0-9A-Fa-f]+.*?func-matches=\d+/\d+.*)",
                line,
            )
            if assigned_match:
                assigned_split = " ".join(assigned_match.group(1).split())
                assigned_range = parse_range(assigned_split)
                continue
        if in_start_hypotheses and not best_exact_hypothesis:
            hypothesis_match = re.match(
                r"\s+(0x[0-9A-Fa-f]+-0x[0-9A-Fa-f]+.*?exact-size=(\d+).*?boundary-conflicts=(\d+).*)",
                line,
            )
            if hypothesis_match and hypothesis_match.group(2) != "0":
                best_exact_hypothesis = " ".join(hypothesis_match.group(1).split())
                best_exact_range = parse_range(best_exact_hypothesis)
                likely_boundary_drift = "delta=" in assigned_split and not assigned_split.startswith(
                    best_exact_hypothesis.split()[0]
                )
                continue
        if in_projected_functions and assigned_range:
            function_match = re.match(
                r"\s+\+0x[0-9A-Fa-f]+\s+(0x[0-9A-Fa-f]+)\s+size=(0x[0-9A-Fa-f]+)\s+(\S+)\s+\[",
                line,
            )
            if function_match:
                start = int(function_match.group(1), 16)
                size = int(function_match.group(2), 16)
                name = function_match.group(3)
                projected_function_rows.append((start, start + size, name))
                continue
        if not best_cluster and re.match(r"\s+0x[0-9A-Fa-f]+-0x[0-9A-Fa-f]+", line):
            best_cluster = " ".join(line.split())

    if assigned_range and projected_function_rows:
        split_start, split_end = assigned_range
        for start, end, name in projected_function_rows:
            if end <= split_start:
                leading_functions.append(name)
            elif start >= split_end:
                trailing_functions.append(name)
            elif start < split_start or end > split_end:
                crossing_functions.append(name)

    return ProbeSummary(
        sections=sections,
        best_cluster=best_cluster,
        assigned_split=assigned_split,
        best_exact_hypothesis=best_exact_hypothesis,
        likely_boundary_drift=likely_boundary_drift,
        leading_functions=leading_functions,
        trailing_functions=trailing_functions,
        crossing_functions=crossing_functions,
        assigned_range=assigned_range,
        best_exact_range=best_exact_range,
    )


def summarize_probe(
    source_path: Path,
    *,
    include_near: bool = False,
    split_entries: list[SplitEntry] | None = None,
    link_hints: ObjectLinkHints | None = None,
) -> str:
    parsed = parse_probe(source_path, include_functions=include_near)
    if isinstance(parsed, str):
        return parsed

    summary_parts = []
    if parsed.sections:
        summary_parts.append("sections " + " ".join(parsed.sections))
    if parsed.assigned_split:
        summary_parts.append("assigned " + parsed.assigned_split)
    if include_near and parsed.best_exact_hypothesis:
        summary_parts.append("best-exact " + parsed.best_exact_hypothesis)
        if parsed.likely_boundary_drift:
            summary_parts.append("likely boundary drift")
        if split_entries and parsed.assigned_range and parsed.best_exact_range:
            previous_name, next_name = find_adjacent_split_names(source_path, split_entries)
            touches = []
            if parsed.best_exact_range[0] < parsed.assigned_range[0] and previous_name:
                touches.append("prev " + previous_name)
            if parsed.best_exact_range[1] > parsed.assigned_range[1] and next_name:
                touches.append("next " + next_name)
            if touches:
                summary_parts.append("touches " + ", ".join(touches))
        if parsed.leading_functions:
            summary_parts.append("before-split " + ", ".join(parsed.leading_functions[:4]))
        if parsed.crossing_functions:
            summary_parts.append("crossing " + ", ".join(parsed.crossing_functions[:4]))
        if parsed.trailing_functions:
            summary_parts.append("after-split " + ", ".join(parsed.trailing_functions[:4]))
    elif parsed.best_cluster:
        summary_parts.append("best " + parsed.best_cluster)
    if link_hints:
        for section in sorted(link_hints.exported_data_symbols):
            names = link_hints.exported_data_symbols[section]
            summary_parts.append(f"exports {section} " + ", ".join(names[:8]))
        for section in sorted(link_hints.local_data_symbols):
            names = link_hints.local_data_symbols[section]
            summary_parts.append(f"locals {section} " + ", ".join(names[:8]))
        if link_hints.owner_hints:
            summary_parts.append("owners " + ", ".join(link_hints.owner_hints))
        if link_hints.undefined_symbols:
            summary_parts.append("undef " + ", ".join(link_hints.undefined_symbols))
    return "; ".join(summary_parts) if summary_parts else "probe produced no summary"


def main() -> int:
    args = get_argparser().parse_args()
    data = json.loads(args.report.read_text())
    split_entries = load_text_splits(args.splits)
    symbol_owners, address_owners = load_symbol_owners(Path("build/GSAE01/main.elf.MAP"))
    symbol_addresses = load_symbol_addresses(Path("config/GSAE01/symbols.txt"))
    sdk_units = [unit for unit in data["units"] if is_sdk(unit)]

    exact_unlinked = []
    near_misses = []

    for unit in sdk_units:
        measures = unit["measures"]
        complete = unit.get("metadata", {}).get("complete", False)
        matched_code = measures.get("matched_code_percent", 0.0)
        matched_funcs = measures.get("matched_functions_percent", 0.0)
        fuzzy = measures.get("fuzzy_match_percent", 0.0)
        entry = (matched_code, matched_funcs, fuzzy, unit)

        if not complete and matched_code == 100.0 and matched_funcs == 100.0:
            exact_unlinked.append(entry)
        elif not complete:
            near_misses.append(entry)

    exact_unlinked.sort(key=lambda row: row[:3], reverse=True)
    near_misses.sort(key=lambda row: row[:3], reverse=True)

    print("Exact-report SDK files still not linked:")
    if exact_unlinked:
        for _, _, _, unit in exact_unlinked:
            print(f"  {unit['name']}")
            if args.probe_exact:
                source_path = unit_name_to_source_path(unit["name"])
                if source_path is None:
                    print("    probe: no source path found")
                else:
                    link_hints = None
                    object_path = unit_name_to_object_path(unit["name"])
                    if object_path is not None:
                        parsed_hints = collect_object_link_hints(
                            object_path,
                            symbol_owners,
                            address_owners,
                            symbol_addresses,
                        )
                        if isinstance(parsed_hints, ObjectLinkHints):
                            link_hints = parsed_hints
                    print(
                        f"    probe: {summarize_probe(source_path, split_entries=split_entries, link_hints=link_hints)}"
                    )
    else:
        print("  (none)")

    print()
    print(f"Top {min(args.limit, len(near_misses))} SDK near-miss files:")
    for matched_code, matched_funcs, fuzzy, unit in near_misses[: args.limit]:
        miss_summary = format_misses(unit)
        print(
            f"  {unit['name']}: code={matched_code:.2f}% funcs={matched_funcs:.2f}% fuzzy={fuzzy:.3f}"
        )
        if miss_summary:
            print(f"    misses: {miss_summary}")
        if args.probe_near:
            source_path = unit_name_to_source_path(unit["name"])
            if source_path is None:
                print("    probe: no source path found")
            else:
                print(
                    f"    probe: {summarize_probe(source_path, include_near=True, split_entries=split_entries)}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
