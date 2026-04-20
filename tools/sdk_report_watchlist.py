#!/usr/bin/env python3
"""Summarize high-signal SDK candidates from build/GSAE01/report.json."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
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
        "--exact-limit",
        type=int,
        default=None,
        help="Maximum number of exact-report-but-unlinked files to print. Defaults to all matching exact files.",
    )
    parser.add_argument(
        "--probe-exact",
        action="store_true",
        help="Run sdk_import_probe.py for exact-report SDK files that are still not linked.",
    )
    parser.add_argument(
        "--probe-near",
        action="store_true",
        help="Run sdk_import_probe.py for SDK near-miss files and summarize split/boundary drift clues.",
    )
    parser.add_argument(
        "--probe-boundary",
        action="store_true",
        help="Run sdk_import_probe.py for boundary-only SDK files and summarize split/boundary drift clues.",
    )
    parser.add_argument(
        "--boundary-limit",
        type=int,
        default=None,
        help="Maximum number of boundary-only SDK files to print. Defaults to the near-miss limit.",
    )
    parser.add_argument(
        "--codegen-limit",
        type=int,
        default=None,
        help="Also print a shortlist of near-miss files that look like codegen-first seams rather than object-shape drift.",
    )
    parser.add_argument(
        "--splits",
        type=Path,
        default=Path("config/GSAE01/splits.txt"),
        help="Path to the splits file used for adjacent-file boundary hints.",
    )
    parser.add_argument(
        "--match",
        default=None,
        help="Only include SDK units whose name contains this substring.",
    )
    parser.add_argument(
        "--reference-splits",
        action="store_true",
        help="Include matching donor split spans from reference_projects for the same normalized source path.",
    )
    parser.add_argument(
        "--reference-sources",
        action="store_true",
        help="Show matching donor source files from reference_projects for the same SDK path or basename.",
    )
    parser.add_argument(
        "--objdump-top",
        action="store_true",
        help="Run function_objdump.py --diff for the top miss of each printed near-miss/codegen entry. Best paired with --match.",
    )
    return parser


@dataclass
class ProbeSummary:
    sections: list[str]
    section_sizes: dict[str, int]
    best_cluster: str
    assigned_split: str
    best_exact_hypothesis: str
    likely_boundary_drift: bool
    leading_functions: list[str]
    trailing_functions: list[str]
    crossing_functions: list[str]
    assigned_range: tuple[int, int] | None
    best_exact_range: tuple[int, int] | None
    assigned_delta: int | None


@dataclass
class SplitEntry:
    name: str
    start: int
    end: int


@dataclass
class ObjectSymbolShape:
    defined_text_symbols: list[str]
    exported_data_symbols: dict[str, list[str]]
    exported_data_symbol_sizes: dict[str, dict[str, int]]
    local_data_symbols: dict[str, list[str]]
    local_data_symbol_sizes: dict[str, dict[str, int]]
    data_symbol_records: dict[str, list["DataSymbolRecord"]]
    undefined_symbols: list[str]
    section_sizes: dict[str, int]


@dataclass
class ObjectLinkHints:
    current: ObjectSymbolShape
    target: ObjectSymbolShape | None
    owner_hints: list[str]


@dataclass(frozen=True)
class DataSymbolRecord:
    name: str
    section: str
    value: int
    size: int
    bind: str


@dataclass
class ReferenceSplitHint:
    repo: str
    version: str
    path: str
    span: int


@dataclass
class ReferenceSourceHint:
    repo: str
    path: str
    match_kind: str


def is_sdk(unit: dict) -> bool:
    return "sdk" in unit.get("metadata", {}).get("progress_categories", [])


def format_misses(unit: dict) -> str:
    misses = [
        f"{fn['name']}={fn.get('fuzzy_match_percent', 100.0):.3f}"
        for fn in unit.get("functions", [])
        if fn.get("fuzzy_match_percent", 100.0) != 100.0
    ]
    return ", ".join(misses[:5])


def top_miss_function(unit: dict) -> str | None:
    misses = [
        fn
        for fn in unit.get("functions", [])
        if fn.get("fuzzy_match_percent", 100.0) != 100.0
    ]
    if not misses:
        return None
    misses.sort(key=lambda fn: fn.get("fuzzy_match_percent", 100.0))
    return misses[0]["name"]


def unit_name_to_source_path(unit_name: str) -> Path | None:
    if not unit_name.startswith("main/"):
        return None

    base = Path("src") / unit_name.removeprefix("main/")
    for candidate in (base.with_suffix(".c"), base.with_suffix(".s"), base):
        if candidate.exists():
            return candidate
    return None


@lru_cache(maxsize=1)
def load_build_ninja_source_map(build_ninja: str = "build.ninja") -> dict[str, str]:
    lines = Path(build_ninja).read_text(encoding="utf-8").splitlines()
    logical_lines: list[str] = []
    index = 0

    while index < len(lines):
        line = lines[index]
        while line.endswith("$") and index + 1 < len(lines):
            index += 1
            line = line[:-1].rstrip() + " " + lines[index].lstrip()
        logical_lines.append(line)
        index += 1

    source_map: dict[str, str] = {}
    for line in logical_lines:
        match = re.match(r"^build\s+(.+?):\s+\S+\s+(\S+)(?:\s+\||$)", line)
        if not match:
            continue
        output = match.group(1).replace("\\", "/")
        source = match.group(2).replace("\\", "/")
        source_map[output] = source

    return source_map


def unit_name_to_probe_source_path(unit_name: str) -> Path | None:
    object_path = unit_name_to_object_path(unit_name)
    if object_path is not None:
        source_map = load_build_ninja_source_map()
        source = source_map.get(object_path.as_posix())
        if source is not None:
            candidate = Path(source)
            if candidate.exists():
                return candidate

    return unit_name_to_source_path(unit_name)


def objdump_hint_for_unit(unit: dict) -> str | None:
    source_path = unit_name_to_source_path(unit["name"])
    top_miss = top_miss_function(unit)
    if source_path is None or top_miss is None:
        return None
    return (
        "python tools/function_objdump.py "
        f"{source_path.relative_to('src').as_posix()} {top_miss} --diff"
    )


def run_objdump_for_unit(unit: dict) -> str:
    source_path = unit_name_to_source_path(unit["name"])
    top_miss = top_miss_function(unit)
    if source_path is None or top_miss is None:
        return "objdump unavailable"

    command = [
        sys.executable,
        "tools/function_objdump.py",
        source_path.relative_to("src").as_posix(),
        top_miss,
        "--diff",
    ]
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        return f"objdump failed ({exc.returncode})"

    return result.stdout.rstrip()


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


def unit_name_to_target_object_path(unit_name: str) -> Path | None:
    if not unit_name.startswith("main/"):
        return None

    base = Path("build/GSAE01/obj") / unit_name.removeprefix("main/")
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


def normalize_split_name_candidates(split_name: str) -> list[str]:
    candidates = [split_name]
    for prefix in ("dolphin/", "Runtime.PPCEABI.H/", "MSL_C/PPCEABI/bare/H/"):
        if split_name.startswith(prefix):
            candidates.append(split_name.removeprefix(prefix))
    return candidates


def find_adjacent_split_names(source_path: Path, split_entries: list[SplitEntry]) -> tuple[str | None, str | None]:
    split_name = source_path_to_split_name(source_path)
    for index, entry in enumerate(split_entries):
        if entry.name != split_name:
            continue
        previous_name = split_entries[index - 1].name if index > 0 else None
        next_name = split_entries[index + 1].name if index + 1 < len(split_entries) else None
        return previous_name, next_name
    return None, None


def format_signed_hex(value: int) -> str:
    sign = "+" if value >= 0 else "-"
    return f"{sign}0x{abs(value):X}"


def format_hex(value: int) -> str:
    return f"0x{value:X}"


def assigned_delta_value(assigned_split: str) -> int | None:
    match = re.search(r"delta=([+-])0x([0-9A-Fa-f]+)", assigned_split)
    if not match:
        return None
    value = int(match.group(2), 16)
    return value if match.group(1) == "+" else -value


def find_overlapping_split_spans(
    source_path: Path,
    target_range: tuple[int, int],
    split_entries: list[SplitEntry],
) -> list[str]:
    split_name = source_path_to_split_name(source_path)
    target_start, target_end = target_range
    overlaps: list[str] = []

    for entry in split_entries:
        if entry.name == split_name:
            continue

        overlap_start = max(target_start, entry.start)
        overlap_end = min(target_end, entry.end)
        if overlap_start < overlap_end:
            overlaps.append(f"{entry.name}=0x{overlap_end - overlap_start:X}")

    return overlaps


def collect_reference_split_hints(source_path: Path, root: Path = Path("reference_projects")) -> list[ReferenceSplitHint]:
    split_name = source_path_to_split_name(source_path)
    candidates = set(normalize_split_name_candidates(split_name))
    hints: list[ReferenceSplitHint] = []

    if not root.exists():
        return hints

    for splits_path in root.glob("*/config/*/splits.txt"):
        repo = splits_path.parents[2].name
        version = splits_path.parent.name
        current_name: str | None = None

        for raw_line in splits_path.read_text(errors="replace").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.endswith(":"):
                current_name = line[:-1]
                continue
            if current_name not in candidates:
                continue

            match = re.match(r"\.text\s+start:(0x[0-9A-Fa-f]+)\s+end:(0x[0-9A-Fa-f]+)", line)
            if match:
                start = int(match.group(1), 16)
                end = int(match.group(2), 16)
                hints.append(
                    ReferenceSplitHint(
                        repo=repo,
                        version=version,
                        path=current_name,
                        span=end - start,
                    )
                )
                break

    hints.sort(key=lambda hint: (hint.path != split_name, hint.span, hint.repo, hint.version))
    return hints


@lru_cache(maxsize=1)
def index_reference_sources(root: str = "reference_projects") -> tuple[tuple[str, str], ...]:
    root_path = Path(root)
    if not root_path.exists():
        return ()

    indexed: list[tuple[str, str]] = []
    for source_path in root_path.rglob("*.c"):
        try:
            relative_path = source_path.relative_to(root_path)
        except ValueError:
            continue
        if len(relative_path.parts) < 2:
            continue
        repo = relative_path.parts[0]
        indexed.append((repo, "/".join(relative_path.parts[1:])))
    return tuple(indexed)


@lru_cache(maxsize=1)
def build_reference_source_indexes(
    root: str = "reference_projects",
) -> tuple[dict[str, tuple[tuple[str, str], ...]], dict[str, tuple[tuple[str, str], ...]]]:
    suffix_index: dict[str, list[tuple[str, str]]] = {}
    basename_index: dict[str, list[tuple[str, str]]] = {}

    for repo, relative_path in index_reference_sources(root):
        basename = Path(relative_path).name
        basename_index.setdefault(basename, []).append((repo, relative_path))

        parts = relative_path.split("/")
        for start in range(len(parts)):
            suffix = "/" + "/".join(parts[start:])
            suffix_index.setdefault(suffix, []).append((repo, relative_path))

    frozen_suffix_index = {
        suffix: tuple(entries)
        for suffix, entries in suffix_index.items()
    }
    frozen_basename_index = {
        basename: tuple(entries)
        for basename, entries in basename_index.items()
    }
    return frozen_suffix_index, frozen_basename_index


def collect_reference_source_hints(
    source_path: Path,
    root: Path = Path("reference_projects"),
) -> list[ReferenceSourceHint]:
    split_name = source_path_to_split_name(source_path)
    suffixes = tuple(f"/{candidate}" for candidate in normalize_split_name_candidates(split_name))
    basename = source_path.name
    hints: list[ReferenceSourceHint] = []
    seen: set[tuple[str, str]] = set()

    suffix_index, basename_index = build_reference_source_indexes(str(root))

    for suffix in suffixes:
        for repo, relative_path in suffix_index.get(suffix, ()):
            key = (repo, relative_path)
            if key in seen:
                continue
            seen.add(key)
            hints.append(ReferenceSourceHint(repo=repo, path=relative_path, match_kind="suffix"))

    for repo, relative_path in basename_index.get(basename, ()):
        key = (repo, relative_path)
        if key in seen:
            continue
        if relative_path.endswith(f"/{basename}"):
            hints.append(ReferenceSourceHint(repo=repo, path=relative_path, match_kind="basename"))

    hints.sort(key=lambda hint: (hint.match_kind != "suffix", hint.repo, hint.path))
    return hints


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


def inspect_object_symbols(object_path: Path) -> ObjectSymbolShape | str:
    try:
        nm_result = subprocess.run(
            ["build/binutils/powerpc-eabi-nm.exe", "-n", str(object_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        section_result = subprocess.run(
            ["build/binutils/powerpc-eabi-objdump.exe", "-h", str(object_path)],
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
    exported_data_symbol_sizes: dict[str, dict[str, int]] = {}
    local_data_symbols: dict[str, list[str]] = {}
    local_data_symbol_sizes: dict[str, dict[str, int]] = {}
    data_symbol_records: dict[str, list[DataSymbolRecord]] = {}
    defined_text_symbols: list[str] = []
    undefined_symbols: list[str] = []
    section_sizes: dict[str, int] = {}
    data_sections = {".data", ".rodata", ".sdata", ".sdata2", ".bss", ".sbss"}
    tracked_sections = data_sections | {".text"}

    for line in nm_result.stdout.splitlines():
        match = re.match(r"\s*(\S+)?\s+([A-Za-z])\s+(\S+)$", line)
        if not match:
            continue
        symbol_type = match.group(2)
        name = match.group(3)
        if symbol_type == "U":
            undefined_symbols.append(name)
        elif symbol_type in {"T", "t"}:
            defined_text_symbols.append(name)

    for line in section_result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 7 or not parts[0].isdigit():
            continue
        section = parts[1]
        if section in tracked_sections:
            section_sizes[section] = int(parts[2], 16)

    for line in objdump_result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 6:
            value_text, bind, symbol_kind, section, size_text, name = parts
        elif len(parts) == 7 and parts[5] == ".hidden":
            value_text, bind, symbol_kind, section, size_text, _, name = parts
        else:
            continue
        if symbol_kind != "O" or section not in data_sections:
            continue
        value = int(value_text, 16)
        size = int(size_text, 16)
        data_symbol_records.setdefault(section, []).append(
            DataSymbolRecord(
                name=name,
                section=section,
                value=value,
                size=size,
                bind=bind,
            )
        )
        if bind == "g":
            exported_data_symbols.setdefault(section, []).append(name)
            exported_data_symbol_sizes.setdefault(section, {})[name] = size
        elif bind == "l":
            local_data_symbols.setdefault(section, []).append(name)
            local_data_symbol_sizes.setdefault(section, {})[name] = size

    return ObjectSymbolShape(
        defined_text_symbols=defined_text_symbols,
        exported_data_symbols=exported_data_symbols,
        exported_data_symbol_sizes=exported_data_symbol_sizes,
        local_data_symbols=local_data_symbols,
        local_data_symbol_sizes=local_data_symbol_sizes,
        data_symbol_records=data_symbol_records,
        undefined_symbols=undefined_symbols,
        section_sizes=section_sizes,
    )


def collect_object_link_hints(
    object_path: Path,
    target_object_path: Path | None,
    symbol_owners: dict[str, str],
    address_owners: dict[int, str],
    symbol_addresses: dict[str, int],
) -> ObjectLinkHints | str:
    current_symbols = inspect_object_symbols(object_path)
    if isinstance(current_symbols, str):
        return current_symbols

    target_symbols = None
    if target_object_path is not None:
        parsed_target = inspect_object_symbols(target_object_path)
        if isinstance(parsed_target, str):
            return parsed_target
        target_symbols = parsed_target

    owner_hints = []
    for names in current_symbols.exported_data_symbols.values():
        for name in names:
            owner = symbol_owners.get(name)
            if owner is None:
                address = symbol_addresses.get(name)
                if address is not None:
                    owner = address_owners.get(address)
            if owner and owner.startswith("auto_"):
                owner_hints.append(f"{name}->{owner}")

    return ObjectLinkHints(
        current=current_symbols,
        target=target_symbols,
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
    section_sizes: dict[str, int] = {}
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
                    section_name = section_match.group(1)
                    section_size = int(section_match.group(2), 16)
                    sections.append(f"{section_name}={section_match.group(2)}")
                    section_sizes[section_name] = section_size
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
        section_sizes=section_sizes,
        best_cluster=best_cluster,
        assigned_split=assigned_split,
        best_exact_hypothesis=best_exact_hypothesis,
        likely_boundary_drift=likely_boundary_drift,
        leading_functions=leading_functions,
        trailing_functions=trailing_functions,
        crossing_functions=crossing_functions,
        assigned_range=assigned_range,
        best_exact_range=best_exact_range,
        assigned_delta=assigned_delta_value(assigned_split),
    )


def object_shape_issue_names(
    link_hints: ObjectLinkHints | None,
    known_functions: list[str] | None,
) -> tuple[list[str], bool]:
    if link_hints is None:
        return [], False

    issue_names: list[str] = []
    known_function_set = set(known_functions or [])
    extra_text = [
        name
        for name in link_hints.current.defined_text_symbols
        if name not in known_function_set
    ]
    if link_hints.target is not None:
        target_text = set(link_hints.target.defined_text_symbols)
        current_text = set(link_hints.current.defined_text_symbols)
        if current_text != target_text:
            issue_names.append("text-shape")

        target_undef = set(link_hints.target.undefined_symbols)
        current_undef = set(link_hints.current.undefined_symbols)
        if current_undef != target_undef:
            issue_names.append("undef-shape")

        if link_hints.current.exported_data_symbols != link_hints.target.exported_data_symbols:
            issue_names.append("exports-data")
        if link_hints.current.exported_data_symbol_sizes != link_hints.target.exported_data_symbol_sizes:
            issue_names.append("exports-size")
        if link_hints.current.local_data_symbols != link_hints.target.local_data_symbols:
            issue_names.append("locals-data")
        if link_hints.current.local_data_symbol_sizes != link_hints.target.local_data_symbol_sizes:
            issue_names.append("locals-size")
    else:
        if extra_text:
            issue_names.append("extra-text")
        if link_hints.current.exported_data_symbols:
            issue_names.append("exports-data")
        if link_hints.current.local_data_symbols:
            issue_names.append("locals-data")
    return issue_names, bool(extra_text)


def ordered_symbol_diff(current: list[str], target: list[str]) -> tuple[list[str], list[str]]:
    target_set = set(target)
    current_set = set(current)
    current_only = [name for name in current if name not in target_set]
    target_only = [name for name in target if name not in current_set]
    return current_only, target_only


def ordered_section_symbol_diff(
    current: dict[str, list[str]],
    target: dict[str, list[str]],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    current_only: dict[str, list[str]] = {}
    target_only: dict[str, list[str]] = {}

    for section in sorted(set(current) | set(target)):
        current_names = current.get(section, [])
        target_names = target.get(section, [])
        current_diff, target_diff = ordered_symbol_diff(current_names, target_names)
        if current_diff:
            current_only[section] = current_diff
        if target_diff:
            target_only[section] = target_diff

    return current_only, target_only


def split_gap_symbols(symbols_by_section: dict[str, list[str]]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    gap_symbols: dict[str, list[str]] = {}
    other_symbols: dict[str, list[str]] = {}

    for section, names in symbols_by_section.items():
        gaps = [name for name in names if name.startswith("gap_")]
        others = [name for name in names if not name.startswith("gap_")]
        if gaps:
            gap_symbols[section] = gaps
        if others:
            other_symbols[section] = others

    return gap_symbols, other_symbols


def is_anonymous_local_symbol(name: str) -> bool:
    return name.startswith("@")


def describe_padding_owner(
    shape: ObjectSymbolShape,
    section: str,
    gap_names: list[str],
) -> str | None:
    records = shape.data_symbol_records.get(section, [])
    if not records:
        return None

    gap_name_set = set(gap_names)
    gap_records = [record for record in records if record.name in gap_name_set]
    if not gap_records:
        return None

    gap_start = min(record.value for record in gap_records)
    owner_candidates = [
        record
        for record in records
        if not record.name.startswith("gap_") and record.value + record.size <= gap_start
    ]
    if owner_candidates:
        owner = max(owner_candidates, key=lambda record: (record.value + record.size, record.value))
        return owner.name
    return f"+0x{gap_start:X}"


def padding_only_section_deltas(
    current: ObjectSymbolShape,
    target: ObjectSymbolShape,
    current_only_exports: dict[str, list[str]],
    target_only_exports: dict[str, list[str]],
    current_gap_exports: dict[str, list[str]],
    target_gap_exports: dict[str, list[str]],
    export_size_deltas: dict[str, list[str]],
    current_only_locals: dict[str, list[str]],
    target_only_locals: dict[str, list[str]],
    local_size_deltas: dict[str, list[str]],
) -> list[str]:
    padding_sections: list[str] = []

    for section in sorted(set(current.section_sizes) | set(target.section_sizes)):
        current_size = current.section_sizes.get(section)
        target_size = target.section_sizes.get(section)
        if current_size is None or target_size is None or target_size <= current_size:
            continue

        target_gap_names = target_gap_exports.get(section, [])
        if not target_gap_names:
            continue

        if current_only_exports.get(section) or target_only_exports.get(section):
            continue
        if export_size_deltas.get(section) or local_size_deltas.get(section):
            continue

        current_local_names = current_only_locals.get(section, [])
        target_local_names = target_only_locals.get(section, [])
        if any(not is_anonymous_local_symbol(name) for name in current_local_names):
            continue
        if any(not is_anonymous_local_symbol(name) for name in target_local_names):
            continue

        target_gap_total = sum(
            target.exported_data_symbol_sizes.get(section, {}).get(name, 0)
            for name in target_gap_names
        )
        current_gap_total = sum(
            current.exported_data_symbol_sizes.get(section, {}).get(name, 0)
            for name in current_gap_exports.get(section, [])
        )
        expected_delta = target_gap_total - current_gap_total
        actual_delta = target_size - current_size
        if expected_delta != actual_delta:
            continue

        padding_entry = f"{section} +0x{actual_delta:X}"
        owner_name = describe_padding_owner(target, section, target_gap_names)
        if owner_name is not None:
            padding_entry += f" after {owner_name}"
        padding_sections.append(padding_entry)

    return padding_sections


def section_symbol_size_diff(
    current: dict[str, dict[str, int]],
    target: dict[str, dict[str, int]],
    *,
    current_label: str = "cur",
    target_label: str = "target",
) -> dict[str, list[str]]:
    deltas: dict[str, list[str]] = {}

    for section in sorted(set(current) | set(target)):
        current_sizes = current.get(section, {})
        target_sizes = target.get(section, {})
        shared_names = [name for name in current_sizes if name in target_sizes]
        section_deltas = []

        for name in shared_names:
            current_size = current_sizes[name]
            target_size = target_sizes[name]
            if current_size == target_size:
                continue
            section_deltas.append(
                f"{name} {current_label}={format_hex(current_size)} {target_label}={format_hex(target_size)}"
            )

        if section_deltas:
            deltas[section] = section_deltas

    return deltas


def section_size_diff(
    current: dict[str, int],
    target: dict[str, int],
    *,
    current_label: str = "cur",
    target_label: str = "target",
) -> list[str]:
    deltas: list[str] = []

    for section in sorted(set(current) | set(target)):
        current_size = current.get(section)
        target_size = target.get(section)
        if current_size == target_size:
            continue
        if current_size is None:
            deltas.append(f"{section} {current_label}=missing {target_label}={format_hex(target_size)}")
        elif target_size is None:
            deltas.append(f"{section} {current_label}={format_hex(current_size)} {target_label}=missing")
        else:
            deltas.append(
                f"{section} {current_label}={format_hex(current_size)} {target_label}={format_hex(target_size)}"
            )

    return deltas


def summarize_probe(
    source_path: Path,
    *,
    include_near: bool = False,
    split_entries: list[SplitEntry] | None = None,
    link_hints: ObjectLinkHints | None = None,
    reference_split_hints: list[ReferenceSplitHint] | None = None,
    known_functions: list[str] | None = None,
) -> str:
    parsed = parse_probe(source_path, include_functions=include_near)
    if isinstance(parsed, str):
        return parsed

    summary_parts = []
    if parsed.sections:
        summary_parts.append("sections " + " ".join(parsed.sections))
    if parsed.assigned_split:
        summary_parts.append("assigned " + parsed.assigned_split)
    assigned_delta = assigned_delta_value(parsed.assigned_split)
    should_summarize_best_exact = bool(
        parsed.best_exact_hypothesis
        and (
            include_near
            or (assigned_delta is not None and assigned_delta != 0)
        )
    )
    if should_summarize_best_exact:
        if not include_near:
            summary_parts.append("report-exact subwindow only")
        summary_parts.append("best-exact " + parsed.best_exact_hypothesis)
        if parsed.likely_boundary_drift:
            summary_parts.append("likely boundary drift")
        if split_entries and parsed.assigned_range and parsed.best_exact_range:
            start_shift = parsed.best_exact_range[0] - parsed.assigned_range[0]
            end_shift = parsed.best_exact_range[1] - parsed.assigned_range[1]
            previous_name, next_name = find_adjacent_split_names(source_path, split_entries)
            tiny_limit = 0x20

            if start_shift or end_shift:
                summary_parts.append(
                    "shift "
                    + f"start={format_signed_hex(start_shift)} "
                    + f"end={format_signed_hex(end_shift)}"
                )

            if (
                start_shift == 0
                and 0 < end_shift <= tiny_limit
                and not parsed.leading_functions
                and not parsed.trailing_functions
            ):
                overhang = "tiny tail overhang " + format_hex(end_shift)
                if next_name:
                    overhang += " into " + next_name
                if parsed.crossing_functions:
                    overhang += " via " + ", ".join(parsed.crossing_functions[:2])
                summary_parts.append(overhang)
            elif (
                end_shift == 0
                and -tiny_limit <= start_shift < 0
                and not parsed.leading_functions
                and not parsed.trailing_functions
            ):
                overhang = "tiny head overhang " + format_hex(-start_shift)
                if previous_name:
                    overhang += " into " + previous_name
                if parsed.crossing_functions:
                    overhang += " via " + ", ".join(parsed.crossing_functions[:2])
                summary_parts.append(overhang)

            touches = []
            if parsed.best_exact_range[0] < parsed.assigned_range[0] and previous_name:
                touches.append("prev " + previous_name)
            if parsed.best_exact_range[1] > parsed.assigned_range[1] and next_name:
                touches.append("next " + next_name)
            if touches:
                summary_parts.append("touches " + ", ".join(touches))
            overlaps = find_overlapping_split_spans(source_path, parsed.best_exact_range, split_entries)
            if overlaps:
                summary_parts.append("overlaps " + ", ".join(overlaps[:4]))
        if parsed.leading_functions:
            summary_parts.append("before-split " + ", ".join(parsed.leading_functions[:4]))
        if parsed.crossing_functions:
            summary_parts.append("crossing " + ", ".join(parsed.crossing_functions[:4]))
        if parsed.trailing_functions:
            summary_parts.append("after-split " + ", ".join(parsed.trailing_functions[:4]))
    elif parsed.best_cluster:
        summary_parts.append("best " + parsed.best_cluster)
    if link_hints:
        if parsed.section_sizes:
            probe_vs_build = section_size_diff(
                parsed.section_sizes,
                link_hints.current.section_sizes,
                current_label="probe",
                target_label="build",
            )
            if probe_vs_build:
                summary_parts.append("probe-vs-build " + ", ".join(probe_vs_build[:6]))
        issue_names, has_extra_text = object_shape_issue_names(link_hints, known_functions)
        if has_extra_text:
            known_function_set = set(known_functions or [])
            extra_text = [
                name
                for name in link_hints.current.defined_text_symbols
                if name not in known_function_set
            ]
            summary_parts.append("extra-text " + ", ".join(extra_text[:8]))
        if link_hints.target is not None:
            section_deltas = section_size_diff(
                link_hints.current.section_sizes,
                link_hints.target.section_sizes,
            )
            current_only_text, target_only_text = ordered_symbol_diff(
                link_hints.current.defined_text_symbols,
                link_hints.target.defined_text_symbols,
            )
            current_only_undef, target_only_undef = ordered_symbol_diff(
                link_hints.current.undefined_symbols,
                link_hints.target.undefined_symbols,
            )
            current_only_exports, target_only_exports = ordered_section_symbol_diff(
                link_hints.current.exported_data_symbols,
                link_hints.target.exported_data_symbols,
            )
            current_gap_exports, current_only_exports = split_gap_symbols(current_only_exports)
            target_gap_exports, target_only_exports = split_gap_symbols(target_only_exports)
            export_size_deltas = section_symbol_size_diff(
                link_hints.current.exported_data_symbol_sizes,
                link_hints.target.exported_data_symbol_sizes,
            )
            current_only_locals, target_only_locals = ordered_section_symbol_diff(
                link_hints.current.local_data_symbols,
                link_hints.target.local_data_symbols,
            )
            local_size_deltas = section_symbol_size_diff(
                link_hints.current.local_data_symbol_sizes,
                link_hints.target.local_data_symbol_sizes,
            )
            padding_sections = padding_only_section_deltas(
                link_hints.current,
                link_hints.target,
                current_only_exports,
                target_only_exports,
                current_gap_exports,
                target_gap_exports,
                export_size_deltas,
                current_only_locals,
                target_only_locals,
                local_size_deltas,
            )

            if section_deltas:
                summary_parts.append("section-sizes " + ", ".join(section_deltas[:6]))
            if padding_sections:
                summary_parts.append("target-end-padding " + ", ".join(padding_sections[:6]))
            if current_only_text:
                summary_parts.append("cur-only-text " + ", ".join(current_only_text[:8]))
            if target_only_text:
                summary_parts.append("target-only-text " + ", ".join(target_only_text[:8]))
            for section in sorted(current_gap_exports):
                summary_parts.append(
                    f"cur-only-gaps {section} " + ", ".join(current_gap_exports[section][:8])
                )
            for section in sorted(target_gap_exports):
                summary_parts.append(
                    f"target-only-gaps {section} " + ", ".join(target_gap_exports[section][:8])
                )
            for section in sorted(current_only_exports):
                summary_parts.append(
                    f"cur-only-exports {section} " + ", ".join(current_only_exports[section][:8])
                )
            for section in sorted(target_only_exports):
                summary_parts.append(
                    f"target-only-exports {section} " + ", ".join(target_only_exports[section][:8])
                )
            for section in sorted(export_size_deltas):
                summary_parts.append(
                    f"export-size {section} " + ", ".join(export_size_deltas[section][:8])
                )
            for section in sorted(current_only_locals):
                summary_parts.append(
                    f"cur-only-locals {section} " + ", ".join(current_only_locals[section][:8])
                )
            for section in sorted(target_only_locals):
                summary_parts.append(
                    f"target-only-locals {section} " + ", ".join(target_only_locals[section][:8])
                )
            for section in sorted(local_size_deltas):
                summary_parts.append(
                    f"local-size {section} " + ", ".join(local_size_deltas[section][:8])
                )
            if current_only_undef:
                summary_parts.append("cur-only-undef " + ", ".join(current_only_undef[:8]))
            if target_only_undef:
                summary_parts.append("target-only-undef " + ", ".join(target_only_undef[:8]))
        else:
            for section in sorted(link_hints.current.exported_data_symbols):
                names = link_hints.current.exported_data_symbols[section]
                summary_parts.append(f"exports {section} " + ", ".join(names[:8]))
            for section in sorted(link_hints.current.local_data_symbols):
                names = link_hints.current.local_data_symbols[section]
                summary_parts.append(f"locals {section} " + ", ".join(names[:8]))
        if link_hints.owner_hints:
            summary_parts.append("owners " + ", ".join(link_hints.owner_hints))
        if link_hints.target is None and link_hints.current.undefined_symbols:
            summary_parts.append("undef " + ", ".join(link_hints.current.undefined_symbols))
    if reference_split_hints:
        refs = [
            f"{hint.repo}:{hint.version} {hint.path}=0x{hint.span:X}"
            for hint in reference_split_hints[:4]
        ]
        summary_parts.append("refs " + ", ".join(refs))
    return "; ".join(summary_parts) if summary_parts else "probe produced no summary"


def format_reference_source_hints(hints: list[ReferenceSourceHint], limit: int = 6) -> str:
    if not hints:
        return "none"

    formatted = []
    for hint in hints[:limit]:
        formatted.append(f"{hint.repo}:{hint.path} ({hint.match_kind})")
    return ", ".join(formatted)


def describe_codegen_seam(parsed: ProbeSummary, link_hints: ObjectLinkHints | None, known_functions: list[str]) -> str:
    issue_names, _ = object_shape_issue_names(link_hints, known_functions)

    if issue_names:
        return "object-shape " + ",".join(issue_names)

    delta = parsed.assigned_delta
    if delta is None:
        return "codegen-first"

    if delta == 0:
        return "codegen-first exact-span"

    if abs(delta) <= 0x20:
        if parsed.crossing_functions and not parsed.leading_functions and not parsed.trailing_functions:
            return "codegen-first tiny-overhang"
        return "codegen-first near-span"

    return "boundary-first"


def main() -> int:
    args = get_argparser().parse_args()
    data = json.loads(args.report.read_text())
    split_entries = load_text_splits(args.splits)
    symbol_owners, address_owners = load_symbol_owners(Path("build/GSAE01/main.elf.MAP"))
    symbol_addresses = load_symbol_addresses(Path("config/GSAE01/symbols.txt"))
    sdk_units = [unit for unit in data["units"] if is_sdk(unit)]
    if args.match:
        match_lower = args.match.lower()
        sdk_units = [unit for unit in sdk_units if match_lower in unit["name"].lower()]

    exact_unlinked = []
    boundary_only = []
    near_misses = []

    for unit in sdk_units:
        measures = unit["measures"]
        complete = unit.get("metadata", {}).get("complete", False)
        matched_code = measures.get("matched_code_percent", 0.0)
        matched_funcs = measures.get("matched_functions_percent", 0.0)
        fuzzy = measures.get("fuzzy_match_percent", 0.0)
        entry = (matched_code, matched_funcs, fuzzy, unit)
        misses = [
            fn
            for fn in unit.get("functions", [])
            if fn.get("fuzzy_match_percent", 100.0) != 100.0
        ]

        if not complete and matched_code == 100.0 and matched_funcs == 100.0:
            exact_unlinked.append(entry)
        elif not complete and not misses:
            boundary_only.append(entry)
        elif not complete:
            near_misses.append(entry)

    exact_unlinked.sort(key=lambda row: row[:3], reverse=True)
    boundary_only.sort(key=lambda row: row[:3], reverse=True)
    near_misses.sort(key=lambda row: row[:3], reverse=True)

    print("Exact-report SDK files still not linked:")
    if exact_unlinked:
        exact_rows = exact_unlinked
        if args.exact_limit is not None:
            exact_rows = exact_unlinked[: args.exact_limit]
        for _, _, _, unit in exact_rows:
            print(f"  {unit['name']}")
            if args.probe_exact:
                source_path = unit_name_to_probe_source_path(unit["name"])
                if source_path is None:
                    print("    probe: no source path found")
                else:
                    link_hints = None
                    split_source_path = unit_name_to_source_path(unit["name"])
                    reference_split_hints = (
                        collect_reference_split_hints(split_source_path)
                        if args.reference_splits and split_source_path is not None
                        else None
                    )
                    reference_source_hints = (
                        collect_reference_source_hints(split_source_path or source_path)
                        if args.reference_sources
                        else None
                    )
                    object_path = unit_name_to_object_path(unit["name"])
                    if object_path is not None:
                        target_object_path = unit_name_to_target_object_path(unit["name"])
                        parsed_hints = collect_object_link_hints(
                            object_path,
                            target_object_path,
                            symbol_owners,
                            address_owners,
                            symbol_addresses,
                        )
                        if isinstance(parsed_hints, ObjectLinkHints):
                            link_hints = parsed_hints
                    print(
                        f"    probe: {summarize_probe(source_path, split_entries=split_entries, link_hints=link_hints, reference_split_hints=reference_split_hints, known_functions=[fn['name'] for fn in unit.get('functions', [])])}"
                    )
                    if reference_source_hints is not None:
                        print(f"    reference-sources: {format_reference_source_hints(reference_source_hints)}")
    else:
        print("  (none)")

    print()
    boundary_rows = boundary_only
    if args.boundary_limit is not None:
        boundary_rows = boundary_only[: args.boundary_limit]
    else:
        boundary_rows = boundary_only[: args.limit]

    print(f"Top {min(len(boundary_rows), len(boundary_only))} boundary-only SDK files:")
    if boundary_rows:
        for matched_code, matched_funcs, fuzzy, unit in boundary_rows:
            print(
                f"  {unit['name']}: code={matched_code:.2f}% funcs={matched_funcs:.2f}% fuzzy={fuzzy:.3f}"
            )
            if args.probe_boundary:
                source_path = unit_name_to_probe_source_path(unit["name"])
                if source_path is None:
                    print("    probe: no source path found")
                else:
                    link_hints = None
                    split_source_path = unit_name_to_source_path(unit["name"])
                    reference_source_hints = (
                        collect_reference_source_hints(split_source_path or source_path)
                        if args.reference_sources
                        else None
                    )
                    object_path = unit_name_to_object_path(unit["name"])
                    if object_path is not None:
                        target_object_path = unit_name_to_target_object_path(unit["name"])
                        parsed_hints = collect_object_link_hints(
                            object_path,
                            target_object_path,
                            symbol_owners,
                            address_owners,
                            symbol_addresses,
                        )
                        if isinstance(parsed_hints, ObjectLinkHints):
                            link_hints = parsed_hints
                    reference_split_hints = (
                        collect_reference_split_hints(split_source_path)
                        if args.reference_splits and split_source_path is not None
                        else None
                    )
                    print(
                        f"    probe: {summarize_probe(source_path, include_near=True, split_entries=split_entries, link_hints=link_hints, reference_split_hints=reference_split_hints, known_functions=[fn['name'] for fn in unit.get('functions', [])])}"
                    )
                    if reference_source_hints is not None:
                        print(f"    reference-sources: {format_reference_source_hints(reference_source_hints)}")
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
        objdump_hint = objdump_hint_for_unit(unit)
        if objdump_hint:
            print(f"    objdump: {objdump_hint}")
        if args.objdump_top and objdump_hint:
            objdump_output = run_objdump_for_unit(unit)
            for line in objdump_output.splitlines():
                print(f"      {line}")
        if args.probe_near:
            source_path = unit_name_to_probe_source_path(unit["name"])
            if source_path is None:
                print("    probe: no source path found")
            else:
                link_hints = None
                split_source_path = unit_name_to_source_path(unit["name"])
                reference_source_hints = (
                    collect_reference_source_hints(split_source_path or source_path)
                    if args.reference_sources
                    else None
                )
                object_path = unit_name_to_object_path(unit["name"])
                if object_path is not None:
                    target_object_path = unit_name_to_target_object_path(unit["name"])
                    parsed_hints = collect_object_link_hints(
                        object_path,
                        target_object_path,
                        symbol_owners,
                        address_owners,
                        symbol_addresses,
                    )
                    if isinstance(parsed_hints, ObjectLinkHints):
                        link_hints = parsed_hints
                reference_split_hints = (
                    collect_reference_split_hints(split_source_path)
                    if args.reference_splits and split_source_path is not None
                    else None
                )
                print(
                    f"    probe: {summarize_probe(source_path, include_near=True, split_entries=split_entries, link_hints=link_hints, reference_split_hints=reference_split_hints, known_functions=[fn['name'] for fn in unit.get('functions', [])])}"
                )
                if reference_source_hints is not None:
                    print(f"    reference-sources: {format_reference_source_hints(reference_source_hints)}")

    if args.codegen_limit is not None:
        print()
        shortlist = []
        scan_limit = max(args.codegen_limit, 5)
        for matched_code, matched_funcs, fuzzy, unit in near_misses[:scan_limit]:
            source_path = unit_name_to_probe_source_path(unit["name"])
            object_path = unit_name_to_object_path(unit["name"])
            if source_path is None or object_path is None:
                continue

            parsed_probe = parse_probe(source_path, include_functions=False)
            if isinstance(parsed_probe, str):
                continue

            parsed_hints = collect_object_link_hints(
                object_path,
                unit_name_to_target_object_path(unit["name"]),
                symbol_owners,
                address_owners,
                symbol_addresses,
            )
            if isinstance(parsed_hints, str):
                continue

            known_functions = [fn["name"] for fn in unit.get("functions", [])]
            seam = describe_codegen_seam(parsed_probe, parsed_hints, known_functions)
            if seam.startswith("object-shape") or seam == "boundary-first":
                continue

            shortlist.append((matched_code, fuzzy, unit, format_misses(unit), seam))

        print(f"Top {min(args.codegen_limit, len(shortlist))} SDK codegen-first files:")
        if shortlist:
            shortlist.sort(key=lambda row: (row[0], row[1], row[2]["name"]), reverse=True)
            for matched_code, fuzzy, unit, miss_summary, seam in shortlist[: args.codegen_limit]:
                print(f"  {unit['name']}: code={matched_code:.2f}% fuzzy={fuzzy:.3f} {seam}")
                if miss_summary:
                    print(f"    misses: {miss_summary}")
                objdump_hint = objdump_hint_for_unit(unit)
                if objdump_hint:
                    print(f"    objdump: {objdump_hint}")
                if args.objdump_top and objdump_hint:
                    objdump_output = run_objdump_for_unit(unit)
                    for line in objdump_output.splitlines():
                        print(f"      {line}")
        else:
            print("  (none)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
