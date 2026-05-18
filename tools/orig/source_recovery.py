from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.orig.dol_xrefs import (
    DolFile,
    FunctionSymbol,
    StringXref,
    format_function_name,
    group_xrefs_by_target,
    load_function_symbols,
    scan_strings,
    scan_text_xrefs,
)


SOURCE_TOKEN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_./-]*\.(?:c|cpp|h|hpp))\b")
SPLIT_HEADER_RE = re.compile(r"^([^\s].*):$")
SPLIT_TEXT_RE = re.compile(r"\.text\s+start:0x([0-9A-Fa-f]+)\s+end:0x([0-9A-Fa-f]+)")
SYMBOL_LINE_RE = re.compile(
    r"^(\S+)\s*=\s*\.(\S+):0x([0-9A-Fa-f]+); // type:(function|object) size:0x([0-9A-Fa-f]+)"
)


@dataclass(frozen=True)
class DebugSourceFile:
    path: str
    text_start: int
    text_end: int
    functions: tuple[FunctionSymbol, ...]
    listed_in_debug_srcfiles: bool


@dataclass(frozen=True)
class RecoveryCandidate:
    retail_text: str
    retail_source_name: str
    retail_address: int
    retail_label: str | None
    retail_message: str | None
    xrefs: tuple[StringXref, ...]
    debug_sources: tuple[DebugSourceFile, ...]
    debug_symbol_hits: tuple[str, ...]
    listed_in_debug_srcfiles: bool


@dataclass(frozen=True)
class RecoveryGroup:
    retail_source_name: str
    retail_addresses: tuple[int, ...]
    retail_texts: tuple[str, ...]
    retail_labels: tuple[str, ...]
    retail_messages: tuple[str, ...]
    xrefs: tuple[StringXref, ...]
    debug_sources: tuple[DebugSourceFile, ...]
    debug_symbol_hits: tuple[str, ...]
    listed_in_debug_srcfiles: bool


def normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def extract_source_name(text: str) -> str | None:
    match = SOURCE_TOKEN_RE.search(text)
    return None if match is None else match.group(1)


def clean_context_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = re.sub(r"\s+", " ", value.strip(" \t\r\n<>:-"))
    return cleaned or None


def extract_retail_context(text: str, source_name: str) -> tuple[str | None, str | None]:
    escaped = re.escape(source_name)

    match = re.search(rf"<\s*{escaped}\s*--\s*([^>]+)>(.*)$", text)
    if match is not None:
        return clean_context_text(match.group(1)), clean_context_text(match.group(2))

    match = re.search(rf"<\s*{escaped}\s+([^>]+)>(.*)$", text)
    if match is not None:
        return clean_context_text(match.group(1)), clean_context_text(match.group(2))

    match = re.search(rf"{escaped}\s*:\s*(.*)$", text)
    if match is not None:
        return None, clean_context_text(match.group(1))

    match = re.search(rf"{escaped}(.*)$", text)
    if match is not None:
        return None, clean_context_text(match.group(1))

    return None, None


def parse_debug_srcfiles(path: Path) -> set[str]:
    basenames: set[str] = set()
    if not path.is_file():
        return basenames
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split(";", 1)[0].strip()
        if not line or not line.endswith((".c", ".cpp", ".h", ".hpp")):
            continue
        basenames.add(Path(line).name.lower())
    return basenames


def parse_debug_split_text_ranges(path: Path) -> dict[str, tuple[int, int]]:
    ranges: dict[str, tuple[int, int]] = {}
    current_path: str | None = None
    current_text: tuple[int, int] | None = None

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        header_match = SPLIT_HEADER_RE.match(line)
        if header_match is not None:
            if current_path is not None and current_text is not None:
                ranges[current_path] = current_text
            current_path = header_match.group(1)
            current_text = None
            continue

        text_match = SPLIT_TEXT_RE.search(line)
        if text_match is not None:
            current_text = (int(text_match.group(1), 16), int(text_match.group(2), 16))

    if current_path is not None and current_text is not None:
        ranges[current_path] = current_text
    return ranges


def parse_all_debug_symbol_names(path: Path) -> list[str]:
    names: list[str] = []
    if not path.is_file():
        return names
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SYMBOL_LINE_RE.match(line)
        if match is None:
            continue
        names.append(match.group(1))
    return names


def build_debug_sources(
    split_ranges: dict[str, tuple[int, int]],
    debug_functions: list[FunctionSymbol],
    debug_srcfiles: set[str],
) -> tuple[dict[str, list[DebugSourceFile]], dict[str, DebugSourceFile]]:
    by_basename: dict[str, list[DebugSourceFile]] = defaultdict(list)
    by_path: dict[str, DebugSourceFile] = {}
    for path, (text_start, text_end) in split_ranges.items():
        functions = tuple(
            function
            for function in debug_functions
            if text_start <= function.address < text_end
        )
        source = DebugSourceFile(
            path=path,
            text_start=text_start,
            text_end=text_end,
            functions=functions,
            listed_in_debug_srcfiles=Path(path).name.lower() in debug_srcfiles,
        )
        by_basename[Path(path).name.lower()].append(source)
        by_path[path] = source
    for values in by_basename.values():
        values.sort(key=lambda item: item.path.lower())
    return by_basename, by_path


def meaningful_function_names(functions: tuple[FunctionSymbol, ...]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for function in functions:
        name = function.name
        lowered = name.lower()
        if name.startswith("fn_"):
            continue
        if re.search(r"func[0-9A-Fa-f]{2,}$", lowered):
            continue
        if name in seen:
            continue
        seen.add(name)
        result.append(name)
    return result


def symbol_stem_hits(symbol_names: list[str], source_name: str, limit: int = 12) -> list[str]:
    stem = normalize_token(Path(source_name).stem)
    hits: list[str] = []
    seen: set[str] = set()
    if not stem:
        return hits
    for name in symbol_names:
        if stem not in normalize_token(name):
            continue
        if name in seen:
            continue
        seen.add(name)
        hits.append(name)
        if len(hits) >= limit:
            break
    return hits


def collect_candidates(
    retail_strings_path: Path,
    retail_symbols_path: Path,
    debug_symbols_path: Path,
    debug_splits_path: Path,
    debug_srcfiles_path: Path,
) -> list[RecoveryCandidate]:
    retail_functions = load_function_symbols(retail_symbols_path)
    debug_functions = load_function_symbols(debug_symbols_path)
    debug_symbol_names = parse_all_debug_symbol_names(debug_symbols_path)
    debug_srcfiles = parse_debug_srcfiles(debug_srcfiles_path)
    debug_split_ranges = parse_debug_split_text_ranges(debug_splits_path)
    debug_sources_by_basename, _debug_sources_by_path = build_debug_sources(
        debug_split_ranges,
        debug_functions,
        debug_srcfiles,
    )

    dol = DolFile(retail_strings_path)
    strings = scan_strings(dol)
    strings_by_address = {entry.address: entry for entry in strings}
    for entry in strings:
        if "source" in entry.tags:
            strings_by_address.setdefault(entry.address + 1, entry)
    xrefs = scan_text_xrefs(dol, strings_by_address, retail_functions)
    xrefs_by_target = group_xrefs_by_target(xrefs)

    candidates: list[RecoveryCandidate] = []
    seen_addresses: set[int] = set()
    for entry in strings:
        if "source" not in entry.tags:
            continue
        source_name = extract_source_name(entry.text)
        if source_name is None:
            continue
        retail_label, retail_message = extract_retail_context(entry.text, source_name)
        if entry.address in seen_addresses:
            continue
        seen_addresses.add(entry.address)
        basename = Path(source_name).name.lower()
        debug_sources = tuple(debug_sources_by_basename.get(basename, []))
        candidates.append(
            RecoveryCandidate(
                retail_text=entry.text,
                retail_source_name=source_name,
                retail_address=entry.address,
                retail_label=retail_label,
                retail_message=retail_message,
                xrefs=tuple(
                    xrefs_by_target.get(entry.address, [])
                    + (xrefs_by_target.get(entry.address + 1, []) if "source" in entry.tags else [])
                ),
                debug_sources=debug_sources,
                debug_symbol_hits=tuple(symbol_stem_hits(debug_symbol_names, source_name)),
                listed_in_debug_srcfiles=basename in debug_srcfiles,
            )
        )
    candidates.sort(
        key=lambda item: (
            not item.xrefs,
            not item.debug_sources,
            not item.listed_in_debug_srcfiles,
            item.retail_source_name.lower(),
            item.retail_address,
        )
    )
    return candidates


def unique_values(values: list[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def dedupe_xrefs(xrefs: list[StringXref]) -> tuple[StringXref, ...]:
    result: list[StringXref] = []
    seen: set[tuple[int, int]] = set()
    for xref in xrefs:
        key = (xref.xref_address, xref.target_address)
        if key in seen:
            continue
        seen.add(key)
        result.append(xref)
    return tuple(result)


def dedupe_debug_sources(sources: list[DebugSourceFile]) -> tuple[DebugSourceFile, ...]:
    result: list[DebugSourceFile] = []
    seen: set[str] = set()
    for source in sources:
        if source.path in seen:
            continue
        seen.add(source.path)
        result.append(source)
    return tuple(result)


def group_candidates(candidates: list[RecoveryCandidate]) -> list[RecoveryGroup]:
    groups_by_name: dict[str, list[RecoveryCandidate]] = defaultdict(list)
    for candidate in candidates:
        groups_by_name[candidate.retail_source_name.lower()].append(candidate)

    groups: list[RecoveryGroup] = []
    for values in groups_by_name.values():
        values.sort(key=lambda item: item.retail_address)
        groups.append(
            RecoveryGroup(
                retail_source_name=values[0].retail_source_name,
                retail_addresses=tuple(candidate.retail_address for candidate in values),
                retail_texts=tuple(candidate.retail_text for candidate in values),
                retail_labels=unique_values(
                    [candidate.retail_label for candidate in values if candidate.retail_label is not None]
                ),
                retail_messages=unique_values(
                    [candidate.retail_message for candidate in values if candidate.retail_message is not None]
                ),
                xrefs=dedupe_xrefs([xref for candidate in values for xref in candidate.xrefs]),
                debug_sources=dedupe_debug_sources(
                    [source for candidate in values for source in candidate.debug_sources]
                ),
                debug_symbol_hits=unique_values(
                    [name for candidate in values for name in candidate.debug_symbol_hits]
                ),
                listed_in_debug_srcfiles=any(candidate.listed_in_debug_srcfiles for candidate in values),
            )
        )

    groups.sort(
        key=lambda item: (
            not item.xrefs,
            not item.debug_sources,
            not item.listed_in_debug_srcfiles,
            item.retail_source_name.lower(),
            item.retail_addresses[0],
        )
    )
    return groups


def search_candidates(groups: list[RecoveryGroup], patterns: list[str]) -> list[RecoveryGroup]:
    lowered = [pattern.lower() for pattern in patterns]
    matches: list[RecoveryGroup] = []
    for candidate in groups:
        fields = [
            candidate.retail_source_name.lower(),
        ]
        fields.extend(text.lower() for text in candidate.retail_texts)
        fields.extend(label.lower() for label in candidate.retail_labels)
        fields.extend(message.lower() for message in candidate.retail_messages)
        fields.extend(source.path.lower() for source in candidate.debug_sources)
        fields.extend(name.lower() for name in candidate.debug_symbol_hits)
        fields.extend(format_function_name(xref).lower() for xref in candidate.xrefs)
        if any(any(pattern in field for field in fields) for pattern in lowered):
            matches.append(candidate)
    return matches


def top_named_functions(debug_sources: tuple[DebugSourceFile, ...], debug_symbol_hits: tuple[str, ...], limit: int = 8) -> list[str]:
    if debug_sources:
        names: list[str] = []
        seen: set[str] = set()
        for source in debug_sources:
            for name in meaningful_function_names(source.functions):
                if name in seen:
                    continue
                seen.add(name)
                names.append(name)
                if len(names) >= limit:
                    return names
        return names
    return list(debug_symbol_hits[:limit])


def summary_markdown(groups: list[RecoveryGroup]) -> str:
    with_xrefs = [candidate for candidate in groups if candidate.xrefs]
    with_debug_sources = [candidate for candidate in groups if candidate.debug_sources]
    with_both = [
        candidate
        for candidate in groups
        if candidate.xrefs and candidate.debug_sources
    ]
    with_symbol_only = [
        candidate
        for candidate in groups
        if not candidate.debug_sources and candidate.debug_symbol_hits
    ]

    lines: list[str] = []
    lines.append("# Retail source-recovery crosswalk")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Retail source-tagged strings recovered: `{sum(len(candidate.retail_texts) for candidate in groups)}`")
    lines.append(f"- Unique retail source basenames recovered: `{len(groups)}`")
    lines.append(f"- Candidates with direct EN xrefs: `{len(with_xrefs)}`")
    lines.append(f"- Candidates with exact sfadebug split-path matches: `{len(with_debug_sources)}`")
    lines.append(f"- Candidates with both EN xrefs and exact debug source matches: `{len(with_both)}`")
    lines.append(f"- Candidates with only debug symbol-stem hits: `{len(with_symbol_only)}`")
    lines.append("")

    lines.append("## High-value exact source matches")
    for candidate in with_both[:10]:
        xref_preview = ", ".join(
            f"`{format_function_name(xref)}`"
            for xref in candidate.xrefs[:3]
        )
        debug_preview = ", ".join(f"`{source.path}`" for source in candidate.debug_sources[:2])
        func_preview = ", ".join(
            f"`{name}`"
            for name in top_named_functions(candidate.debug_sources, candidate.debug_symbol_hits, 6)
        )
        address_preview = ", ".join(f"`0x{address:08X}`" for address in candidate.retail_addresses[:3])
        lines.append(
            f"- `{candidate.retail_source_name}` retail strings={len(candidate.retail_texts)} addresses={address_preview}"
        )
        if candidate.retail_labels:
            lines.append("  retail labels: " + ", ".join(f"`{label}`" for label in candidate.retail_labels[:4]))
        if candidate.retail_messages:
            lines.append("  retail messages: " + ", ".join(f"`{message}`" for message in candidate.retail_messages[:2]))
        lines.append(f"  EN xrefs: {xref_preview}")
        lines.append(f"  sfadebug paths: {debug_preview}")
        if func_preview:
            lines.append(f"  named debug functions: {func_preview}")
    lines.append("")

    if with_symbol_only:
        lines.append("## Partial matches worth chasing")
        for candidate in with_symbol_only[:8]:
            func_preview = ", ".join(f"`{name}`" for name in candidate.debug_symbol_hits[:6])
            xref_preview = ", ".join(
                f"`{format_function_name(xref)}`"
                for xref in candidate.xrefs[:3]
            )
            address_preview = ", ".join(f"`0x{address:08X}`" for address in candidate.retail_addresses[:4])
            lines.append(
                f"- `{candidate.retail_source_name}` retail strings={len(candidate.retail_texts)} addresses={address_preview}"
            )
            if candidate.retail_labels:
                lines.append("  retail labels: " + ", ".join(f"`{label}`" for label in candidate.retail_labels[:4]))
            if candidate.retail_messages:
                lines.append("  retail messages: " + ", ".join(f"`{message}`" for message in candidate.retail_messages[:2]))
            if candidate.xrefs:
                lines.append(f"  EN xrefs: {xref_preview}")
            lines.append(f"  debug symbol hits: {func_preview}")
        lines.append("")

    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_recovery.py`")
    lines.append("- Focus one source or subsystem: `python tools/orig/source_recovery.py --search curves camcontrol`")
    lines.append("- CSV dump: `python tools/orig/source_recovery.py --format csv`")
    return "\n".join(lines)


def search_markdown(candidates: list[RecoveryGroup], patterns: list[str]) -> str:
    matches = search_candidates(candidates, patterns)
    lines = ["# Source-recovery search", ""]
    if not matches:
        lines.append("- No matching candidates.")
        return "\n".join(lines)

    for candidate in matches:
        lines.append(f"- `{candidate.retail_source_name}`")
        lines.append(
            "  retail addresses: " + ", ".join(f"`0x{address:08X}`" for address in candidate.retail_addresses[:6])
        )
        for text in candidate.retail_texts[:4]:
            lines.append(f"  retail string: `{text}`")
        if candidate.retail_labels:
            lines.append("  retail labels: " + ", ".join(f"`{label}`" for label in candidate.retail_labels[:6]))
        if candidate.retail_messages:
            lines.append("  retail messages: " + ", ".join(f"`{message}`" for message in candidate.retail_messages[:4]))
        if candidate.xrefs:
            for xref in candidate.xrefs[:6]:
                lines.append(
                    f"  EN xref: `0x{xref.xref_address:08X}` `{format_function_name(xref)}`"
                )
        else:
            lines.append("  EN xref: none")
        if candidate.debug_sources:
            for source in candidate.debug_sources[:3]:
                lines.append(
                    f"  debug path: `{source.path}` text=`0x{source.text_start:08X}`-`0x{source.text_end:08X}`"
                )
                named = meaningful_function_names(source.functions)[:8]
                if named:
                    lines.append("  named functions: " + ", ".join(f"`{name}`" for name in named))
        elif candidate.debug_symbol_hits:
            lines.append(
                "  debug symbol hits: "
                + ", ".join(f"`{name}`" for name in candidate.debug_symbol_hits[:10])
            )
        else:
            lines.append("  debug-side match: none")
    return "\n".join(lines)


def rows_to_csv(candidates: list[RecoveryCandidate]) -> str:
    fieldnames = [
        "retail_source_name",
        "retail_address",
        "retail_text",
        "retail_label",
        "retail_message",
        "xref_count",
        "en_functions",
        "debug_source_paths",
        "debug_named_functions",
        "debug_symbol_hits",
        "listed_in_debug_srcfiles",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for candidate in candidates:
        writer.writerow(
            {
                "retail_source_name": candidate.retail_source_name,
                "retail_address": f"0x{candidate.retail_address:08X}",
                "retail_text": candidate.retail_text,
                "retail_label": candidate.retail_label or "",
                "retail_message": candidate.retail_message or "",
                "xref_count": len(candidate.xrefs),
                "en_functions": ",".join(format_function_name(xref) for xref in candidate.xrefs),
                "debug_source_paths": ",".join(source.path for source in candidate.debug_sources),
                "debug_named_functions": ",".join(
                    top_named_functions(candidate.debug_sources, candidate.debug_symbol_hits, 12)
                ),
                "debug_symbol_hits": ",".join(candidate.debug_symbol_hits[:12]),
                "listed_in_debug_srcfiles": str(candidate.listed_in_debug_srcfiles).lower(),
            }
        )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crosswalk retail EN source-tag strings to current EN xrefs and sfadebug source/function names."
    )
    parser.add_argument(
        "--dol",
        type=Path,
        default=Path("orig/GSAE01/sys/main.dol"),
        help="Path to the retail EN main.dol.",
    )
    parser.add_argument(
        "--symbols",
        type=Path,
        default=Path("config/GSAE01/symbols.txt"),
        help="Current EN symbols.txt for naming retail xref callsites.",
    )
    parser.add_argument(
        "--debug-symbols",
        type=Path,
        default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"),
        help="sfadebug symbols.txt used as side evidence for source/function names.",
    )
    parser.add_argument(
        "--debug-splits",
        type=Path,
        default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"),
        help="sfadebug splits.txt used to group debug functions back into source files.",
    )
    parser.add_argument(
        "--debug-srcfiles",
        type=Path,
        default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"),
        help="sfadebug string-derived source filename inventory.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "csv"),
        default="markdown",
        help="Output format.",
    )
    parser.add_argument(
        "--search",
        nargs="+",
        help="Case-insensitive substring search across retail names, EN xrefs, debug paths, and debug function names.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    candidates = collect_candidates(
        retail_strings_path=args.dol,
        retail_symbols_path=args.symbols,
        debug_symbols_path=args.debug_symbols,
        debug_splits_path=args.debug_splits,
        debug_srcfiles_path=args.debug_srcfiles,
    )
    groups = group_candidates(candidates)

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(candidates))
        elif args.search:
            sys.stdout.write(search_markdown(groups, args.search))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(groups))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
