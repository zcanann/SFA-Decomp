#!/usr/bin/env python3
"""One-page SDK progress sanity report.

This does not replace the focused SDK tools. It stitches together the counts
that tend to get confused during linkage work: active report units, configured
SDK objects, active NonMatching debt, donor-backed dormant files, and inline asm
that clean donors do not need.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from sdk_donor_asm_audit import asm_count, donor_source_index, is_matching_state
from sdk_linkage_candidates import diff_candidate, parse_nonmatching_objects
from sdk_missing_unit_audit import DEFAULT_REFERENCES
from sdk_reference_inventory import (
    build_inventory,
    canonicalize_sdk_path,
    load_configured_objects,
    load_target_splits,
    parse_refspec,
    source_exists,
)


ROOT = Path(__file__).resolve().parents[1]
SDK_PREFIXES = ("dolphin/", "Runtime.PPCEABI.H/")
SOURCE_SUFFIX_RE = re.compile(r"\.(?:c|cpp|cp|cxx|s|S)$")
INLINE_ASM_CAVEATS = {
    "dolphin/os/OSFont.c": (
        "close Sunshine/AC donor, but SFA's current parser/source shape still misses the strict hash"
    ),
    "dolphin/TRK_MINNOW_DOLPHIN/MWTrace.c": "FFCC donor is an empty stub; SFA target has a real trace recorder",
    "dolphin/gx/GXInit.c": "tiny WPAR helper likely still needs inline mfspr shape",
    "dolphin/MSL_C/PPCEABI/bare/H/rand.c": (
        "donor rand/srand only; SFA unit also carries reciprocal/trig helper code"
    ),
}
SDK_PLACEHOLDER_CAVEATS = {
    "main/unknown/autos/placeholder_8032C984": (
        "OSContext FPU-unavailable string; splitting to OSErrorContext.c compiles but changes "
        "__OSContextInit prologue scheduling"
    ),
    "main/unknown/autos/placeholder_803D8888": (
        "MetroTRK BSS aggregate; lbl_803D8888 is used as a UART buffer that overlaps later labels"
    ),
}
OBJDUMP = ROOT / "build" / "binutils" / "powerpc-eabi-objdump.exe"


@dataclass(frozen=True)
class LinkageArgs:
    version: str
    active_only: bool = True
    show_errors: bool = False
    include_game_classified: bool = False


def active_sdk_units(version: str) -> tuple[set[str], int]:
    config_path = ROOT / "build" / version / "config.json"
    if not config_path.is_file():
        raise SystemExit(f"Missing build config: {config_path}; run configure.py first")

    config = json.loads(config_path.read_text())
    active: set[str] = set()
    for unit in config.get("units", []):
        name = unit.get("name", "").replace("\\", "/")
        if name.startswith(SDK_PREFIXES):
            active.add(canonicalize_sdk_path(name))
    _report_total, report_complete = progress_report_counts(version) or (len(active), 0)
    return active, report_complete


def report_sdk_units(version: str) -> set[str]:
    report_path = ROOT / "build" / version / "report.json"
    if not report_path.is_file():
        return set()
    report = json.loads(report_path.read_text())
    return {
        normalize_report_unit_name(unit.get("name", ""))
        for unit in report.get("units", [])
        if "sdk" in unit.get("metadata", {}).get("progress_categories", [])
    }


def normalize_report_unit_name(name: str) -> str:
    path = name.replace("\\", "/")
    if path.startswith("main/"):
        path = path[len("main/") :]
    return path


def unit_basename(path: str) -> str:
    return SOURCE_SUFFIX_RE.sub("", path)


def configured_sdk_objects() -> set[str]:
    _exact, canonical = load_configured_objects()
    return {path for path in canonical if path.startswith(SDK_PREFIXES)}


def target_sdk_splits(version: str) -> set[str]:
    _exact, canonical = load_target_splits(version)
    return {path for path in canonical if path.startswith(SDK_PREFIXES)}


def fmt_percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:5.1f}%"


def linkage_rows(version: str, limit: int, path_filter: str | None) -> list[object]:
    args = LinkageArgs(version=version)
    sources = parse_nonmatching_objects(ROOT / "configure.py")
    rows = []
    for source in sources:
        if path_filter and path_filter.lower() not in source.lower():
            continue
        candidate = diff_candidate(args, source)
        if candidate is None or candidate.error:
            continue
        rows.append(candidate)
    rows.sort(
        key=lambda row: (
            row.code_percent is not None,
            row.code_percent or -1.0,
            row.data_percent if row.data_percent is not None else 101.0,
            row.text_size,
        ),
        reverse=True,
    )
    return rows[:limit]


def donor_backed_dormant(version: str, limit: int, path_filter: str | None) -> list[tuple[str, int, int, int]]:
    references = [parse_refspec(value) for value in DEFAULT_REFERENCES]
    inventory = build_inventory(references)
    active, _complete = active_sdk_units(version)
    configured = configured_sdk_objects()
    splits = target_sdk_splits(version)

    rows: list[tuple[str, int, int, int]] = []
    for path, per_ref in inventory.items():
        canonical = canonicalize_sdk_path(path)
        if path_filter and path_filter.lower() not in canonical.lower():
            continue
        if canonical in active or canonical in splits:
            continue
        if canonical not in configured or not source_exists(canonical):
            continue
        spans = [unit.text_size for unit in per_ref.values()]
        funcs = [unit.text_funcs for unit in per_ref.values()]
        rows.append((canonical, len(per_ref), max(spans), max(funcs)))

    rows.sort(key=lambda row: (-row[1], row[3] == 1, -row[2], row[0]))
    return rows[:limit]


def clean_donor_asm_rows(version: str, limit: int, path_filter: str | None) -> list[tuple[str, int, str, str | None]]:
    index = donor_source_index(
        (
            "animal_crossing",
            "final_fantasy_crystal_chronicles",
            "marioparty4",
            "metroid_prime",
            "pikmin",
            "pikmin2",
            "super_mario_sunshine",
            "twilight_princess",
            "wind_waker",
        )
    )
    active, _complete = active_sdk_units(version)
    rows: list[tuple[str, int, str, str | None]] = []
    for source in sorted(active):
        if not source.endswith((".c", ".cpp", ".cp")):
            continue
        if path_filter and path_filter.lower() not in source.lower():
            continue
        local = ROOT / "src" / Path(source)
        if not local.is_file():
            continue
        local_asm = asm_count(local)
        if local_asm == 0:
            continue
        donors = [
            donor
            for donor in index.get(canonicalize_sdk_path(source), [])
            if donor.asm_count == 0 and is_matching_state(donor.state)
        ]
        if donors:
            best = min(donors, key=lambda donor: (donor.project, donor.path.as_posix()))
            rows.append(
                (
                    source,
                    local_asm,
                    f"{best.project}:{best.path.relative_to(ROOT).as_posix()}",
                    INLINE_ASM_CAVEATS.get(source),
                )
            )
    rows.sort(key=lambda row: (-row[1], row[0]))
    return rows[:limit]


def progress_report_counts(version: str) -> tuple[int, int] | None:
    report_path = ROOT / "build" / version / "report.json"
    if not report_path.is_file():
        return None
    report = json.loads(report_path.read_text())
    sdk_units = [
        unit
        for unit in report.get("units", [])
        if "sdk" in unit.get("metadata", {}).get("progress_categories", [])
    ]
    return len(sdk_units), sum(1 for unit in sdk_units if unit.get("metadata", {}).get("complete"))


def report_incomplete_sdk_units(version: str, limit: int, path_filter: str | None) -> list[dict]:
    report_path = ROOT / "build" / version / "report.json"
    if not report_path.is_file():
        return []
    report = json.loads(report_path.read_text())
    rows = []
    for unit in report.get("units", []):
        metadata = unit.get("metadata", {})
        if "sdk" not in metadata.get("progress_categories", []):
            continue
        if metadata.get("complete"):
            continue
        source_path = metadata.get("source_path", "")
        name = unit.get("name", "")
        if path_filter and path_filter.lower() not in f"{name} {source_path}".lower():
            continue
        rows.append(unit)
    rows.sort(
        key=lambda unit: (
            float(unit.get("measures", {}).get("matched_code_percent") or 0.0),
            float(unit.get("measures", {}).get("matched_data_percent") or -1.0),
            unit.get("name", ""),
        ),
        reverse=True,
    )
    return rows[:limit]


def current_object_for_target(target_object: Path, version: str) -> Path:
    return ROOT / Path(
        target_object.relative_to(ROOT).as_posix().replace(f"build/{version}/obj/", f"build/{version}/src/")
    )


def objdump_symbol(object_path: Path, symbol: str) -> str | None:
    if not OBJDUMP.is_file() or not object_path.is_file():
        return None
    result = subprocess.run(
        [str(OBJDUMP), "-drz", f"--disassemble={symbol}", str(object_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def savefpr_symbols(text: str | None) -> set[str]:
    if not text:
        return set()
    return set(re.findall(r"_(?:save|rest)fpr_\d+", text))


def fpr_save_mismatch_rows(version: str, limit: int, path_filter: str | None) -> list[tuple[str, str, str, str]]:
    rows = []
    for unit in report_incomplete_sdk_units(version, limit=999, path_filter=path_filter):
        metadata = unit.get("metadata", {})
        source_path = metadata.get("source_path") or unit.get("name", "")
        target_object = ROOT / Path(metadata.get("object") or "")
        if not target_object.is_file():
            config_path = ROOT / "build" / version / "config.json"
            if config_path.is_file():
                report_name = unit_basename(unit.get("name", "").replace("main/", "", 1))
                for config_unit in json.loads(config_path.read_text()).get("units", []):
                    config_name = unit_basename(config_unit.get("name", "").replace("\\", "/"))
                    if config_name == report_name:
                        target_object = ROOT / Path(config_unit["object"])
                        break
        current_object = current_object_for_target(target_object, version)
        for function in unit.get("functions", []):
            symbol = function.get("name")
            if not symbol:
                continue
            target_fprs = savefpr_symbols(objdump_symbol(target_object, symbol))
            current_fprs = savefpr_symbols(objdump_symbol(current_object, symbol))
            if target_fprs == current_fprs:
                continue
            rows.append(
                (
                    source_path.replace("src/", "", 1),
                    symbol,
                    ",".join(sorted(target_fprs)) or "-",
                    ",".join(sorted(current_fprs)) or "-",
                )
            )
    rows.sort()
    return rows[:limit]


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize SDK linkage/split sanity signals.")
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--path-contains", default=None)
    args = parser.parse_args()

    active, active_complete = active_sdk_units(args.version)
    report_sdk = report_sdk_units(args.version)
    active_basenames = {unit_basename(path) for path in active}
    configured = configured_sdk_objects()
    splits = target_sdk_splits(args.version)
    report_counts = progress_report_counts(args.version)

    report_text = "missing"
    if report_counts is not None:
        report_text = f"{report_counts[1]}/{report_counts[0]}"
    print(
        "summary "
        f"report-sdk-units={report_text} "
        f"build-active-sdk-objects={len(active)} configured-sdk-objects={len(configured)} "
        f"split-backed={len(splits)} dormant-configured={len(configured - active - splits)}"
    )

    report_only = sorted(report_sdk - active_basenames)
    path_only = sorted(active_basenames - report_sdk)
    if report_only or path_only:
        print("\nsdk-category-deltas")
        if report_only:
            print("  report-sdk-not-path-sdk=" + ", ".join(report_only))
            for path in report_only:
                caveat = SDK_PLACEHOLDER_CAVEATS.get(path)
                if caveat:
                    print(f"    note {path}: {caveat}")
        if path_only:
            print("  path-sdk-not-report-sdk=" + ", ".join(path_only))

    print("\nreport-incomplete-sdk-units")
    for unit in report_incomplete_sdk_units(args.version, args.limit, args.path_contains):
        measures = unit.get("measures", {})
        metadata = unit.get("metadata", {})
        source_path = metadata.get("source_path", unit.get("name", "")).replace("src/", "", 1)
        print(
            f"  code={fmt_percent(float(measures.get('matched_code_percent') or 0.0))} "
            f"data={fmt_percent(float(measures.get('matched_data_percent')) if measures.get('matched_data_percent') is not None else None)} "
            f"text=0x{int(measures.get('total_code') or 0):X} funcs={len(unit.get('functions', [])):2d} "
            f"path={source_path}"
        )

    print("\nfpr-save-mismatches")
    for path, symbol, target_fprs, current_fprs in fpr_save_mismatch_rows(args.version, args.limit, args.path_contains):
        print(f"  path={path} symbol={symbol} target={target_fprs} current={current_fprs}")

    print("\nactive-nonmatching-near-misses")
    for row in linkage_rows(args.version, args.limit, args.path_contains):
        print(
            f"  code={fmt_percent(row.code_percent)} data={fmt_percent(row.data_percent)} "
            f"text=0x{row.text_size:X} bad={row.bad_symbols:2d} path={row.path}"
        )

    print("\ndormant-donor-backed-configured")
    for path, refs, span, funcs in donor_backed_dormant(args.version, args.limit, args.path_contains):
        print(f"  refs={refs:2d} max-text=0x{span:X} max-funcs={funcs} path={path}")

    print("\ninline-asm-with-clean-matching-donor")
    for path, count, donor, caveat in clean_donor_asm_rows(args.version, args.limit, args.path_contains):
        suffix = f" note={caveat}" if caveat else ""
        print(f"  asm={count:2d} path={path} donor={donor}{suffix}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
