from __future__ import annotations

import argparse
import csv
import io
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.orig.dol_xrefs import FunctionSymbol, load_function_symbols
from tools.orig.source_matrix import (
    build_source_variant_index,
    collect_all_bundle_source_hits,
    default_bundle_specs,
)
from tools.orig.source_recovery import RecoveryGroup, format_function_name, parse_debug_split_text_ranges
from tools.orig.source_reference_hints import ReferenceHint, build_groups, collect_reference_hints


@dataclass(frozen=True)
class SplitRange:
    path: str
    start: int
    end: int


@dataclass(frozen=True)
class BoundaryHint:
    retail_source_name: str
    alias_names: tuple[str, ...]
    bundle_ids: tuple[str, ...]
    suggested_path: str
    bucket: str | None
    retail_labels: tuple[str, ...]
    retail_messages: tuple[str, ...]
    xref_count: int
    en_xrefs: tuple[str, ...]
    xref_functions: tuple[FunctionSymbol, ...]
    span_start: int | None
    span_end: int | None
    split_status: str
    current_split_paths: tuple[str, ...]
    gap_start: int | None
    gap_end: int | None
    gap_prev_path: str | None
    gap_next_path: str | None
    debug_paths: tuple[str, ...]
    debug_named_functions: tuple[str, ...]
    reference_paths: tuple[str, ...]
    reference_symbol_hints: tuple[str, ...]
    nearby_before: tuple[str, ...]
    nearby_after: tuple[str, ...]
    score: int

    @property
    def span_size(self) -> int | None:
        if self.span_start is None or self.span_end is None:
            return None
        return self.span_end - self.span_start


def unique_strings(values: list[str], limit: int | None = None) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
        if limit is not None and len(result) >= limit:
            break
    return tuple(result)


def top_bucket(path: str) -> str | None:
    normalized = path.replace("\\", "/").strip("/")
    if not normalized or "/" not in normalized:
        return None
    return normalized.split("/", 1)[0]


def build_split_ranges(path: Path) -> list[SplitRange]:
    ranges: list[SplitRange] = []
    for split_path, (start, end) in parse_debug_split_text_ranges(path).items():
        ranges.append(SplitRange(path=split_path, start=start, end=end))
    ranges.sort(key=lambda item: (item.start, item.end, item.path.lower()))
    return ranges


def format_symbol_span(function: FunctionSymbol) -> str:
    return f"{function.name}@0x{function.address:08X}-0x{function.address + function.size:08X}"


def symbol_neighbors(
    current_functions: list[FunctionSymbol],
    xref_functions: tuple[FunctionSymbol, ...],
    radius: int = 3,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not xref_functions:
        return (), ()
    index_by_address = {function.address: index for index, function in enumerate(current_functions)}
    start_index = min(index_by_address[function.address] for function in xref_functions)
    end_index = max(index_by_address[function.address] for function in xref_functions)

    before = [
        format_symbol_span(current_functions[index])
        for index in range(max(0, start_index - radius), start_index)
    ]
    after = [
        format_symbol_span(current_functions[index])
        for index in range(end_index + 1, min(len(current_functions), end_index + 1 + radius))
    ]
    return tuple(before), tuple(after)


def overlapping_split_paths(ranges: list[SplitRange], start: int, end: int) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for split_range in ranges:
        if start < split_range.end and split_range.start < end and split_range.path not in seen:
            seen.add(split_range.path)
            values.append(split_range.path)
    return tuple(values)


def split_gap_context(
    ranges: list[SplitRange],
    start: int | None,
    end: int | None,
) -> tuple[str, tuple[str, ...], int | None, int | None, str | None, str | None]:
    if start is None or end is None:
        return "no-xrefs", (), None, None, None, None

    paths = overlapping_split_paths(ranges, start, end)
    if paths:
        status = "single-split" if len(paths) == 1 else "multi-split"
        return status, paths, None, None, None, None

    prev_range = max((item for item in ranges if item.end <= start), default=None, key=lambda item: item.end)
    next_range = min((item for item in ranges if item.start >= end), default=None, key=lambda item: item.start)
    gap_start = None if prev_range is None else prev_range.end
    gap_end = None if next_range is None else next_range.start
    prev_path = None if prev_range is None else prev_range.path
    next_path = None if next_range is None else next_range.path
    return "unsplit", (), gap_start, gap_end, prev_path, next_path


def suggested_path(hint: ReferenceHint) -> str:
    if hint.current_debug_paths:
        return hint.current_debug_paths[0].replace("\\", "/")
    if hint.reference_configure_paths:
        return hint.reference_configure_paths[0].replace("\\", "/")
    return Path(hint.retail_source_name).name


def hint_bucket(hint: ReferenceHint, selected_path: str) -> str | None:
    bucket = top_bucket(selected_path)
    if bucket is not None:
        return bucket
    if hint.inferred_bucket is not None:
        return hint.inferred_bucket.bucket
    return None


def boundary_score(
    group: RecoveryGroup,
    hint: ReferenceHint,
    split_status: str,
    bundle_ids: tuple[str, ...],
    xref_functions: tuple[FunctionSymbol, ...],
) -> int:
    score = len(bundle_ids) * 250
    score += len(group.xrefs) * 180
    score += len(xref_functions) * 140
    score += len(group.retail_labels) * 120
    score += len(group.retail_messages[:2]) * 40
    if hint.current_debug_paths:
        score += 120
    if hint.reference_configure_paths:
        score += 80
    if hint.reference_symbol_hints:
        score += 50
    if split_status == "unsplit":
        score += 160
    if split_status == "no-xrefs":
        score -= 240
    return score


def build_boundary_hints(
    groups: list[RecoveryGroup],
    reference_hints: list[ReferenceHint],
    current_functions: list[FunctionSymbol],
    current_splits: list[SplitRange],
) -> list[BoundaryHint]:
    reference_by_name = {hint.retail_source_name.lower(): hint for hint in reference_hints}
    function_by_address = {function.address: function for function in current_functions}
    variant_index = build_source_variant_index(collect_all_bundle_source_hits(default_bundle_specs()))

    hints: list[BoundaryHint] = []
    for group in groups:
        hint = reference_by_name[group.retail_source_name.lower()]
        evidence = variant_index.get(group.retail_source_name.lower())
        alias_names = () if evidence is None else evidence.alias_names
        bundle_ids = () if evidence is None else evidence.all_bundle_ids

        xref_functions = unique_xref_functions(group, function_by_address)
        span_start = None if not xref_functions else min(function.address for function in xref_functions)
        span_end = None if not xref_functions else max(function.address + function.size for function in xref_functions)
        split_status, current_split_paths, gap_start, gap_end, gap_prev_path, gap_next_path = split_gap_context(
            current_splits,
            span_start,
            span_end,
        )
        before, after = symbol_neighbors(current_functions, xref_functions)
        selected_path = suggested_path(hint)

        hints.append(
            BoundaryHint(
                retail_source_name=group.retail_source_name,
                alias_names=alias_names,
                bundle_ids=bundle_ids,
                suggested_path=selected_path,
                bucket=hint_bucket(hint, selected_path),
                retail_labels=group.retail_labels,
                retail_messages=group.retail_messages,
                xref_count=len(group.xrefs),
                en_xrefs=tuple(format_function_name(xref) for xref in group.xrefs),
                xref_functions=xref_functions,
                span_start=span_start,
                span_end=span_end,
                split_status=split_status,
                current_split_paths=current_split_paths,
                gap_start=gap_start,
                gap_end=gap_end,
                gap_prev_path=gap_prev_path,
                gap_next_path=gap_next_path,
                debug_paths=tuple(source.path for source in group.debug_sources),
                debug_named_functions=tuple(group.debug_symbol_hits[:8]),
                reference_paths=hint.reference_configure_paths,
                reference_symbol_hints=hint.reference_symbol_hints,
                nearby_before=before,
                nearby_after=after,
                score=boundary_score(group, hint, split_status, bundle_ids, xref_functions),
            )
        )

    hints.sort(
        key=lambda item: (
            item.split_status == "no-xrefs",
            item.split_status != "unsplit",
            -item.score,
            item.retail_source_name.lower(),
        )
    )
    return hints


def unique_xref_functions(
    group: RecoveryGroup,
    function_by_address: dict[int, FunctionSymbol],
) -> tuple[FunctionSymbol, ...]:
    values: list[FunctionSymbol] = []
    seen: set[int] = set()
    for xref in group.xrefs:
        if xref.function_start is None:
            continue
        function = function_by_address.get(xref.function_start)
        if function is None or function.address in seen:
            continue
        seen.add(function.address)
        values.append(function)
    values.sort(key=lambda item: item.address)
    return tuple(values)


def describe_gap(hint: BoundaryHint) -> str:
    if hint.split_status == "no-xrefs":
        return "no EN xrefs recovered"
    if hint.split_status == "single-split":
        return f"inside current split `{hint.current_split_paths[0]}`"
    if hint.split_status == "multi-split":
        return "crosses current splits " + ", ".join(f"`{path}`" for path in hint.current_split_paths)
    parts: list[str] = ["outside current `splits.txt` coverage"]
    if hint.gap_start is not None and hint.gap_end is not None:
        parts.append(f"in gap `0x{hint.gap_start:08X}-0x{hint.gap_end:08X}`")
    elif hint.gap_end is not None:
        parts.append(f"before split coverage starts at `0x{hint.gap_end:08X}`")
    elif hint.gap_start is not None:
        parts.append(f"after split coverage ends at `0x{hint.gap_start:08X}`")
    if hint.gap_prev_path is not None:
        parts.append(f"prev split `{hint.gap_prev_path}`")
    if hint.gap_next_path is not None:
        parts.append(f"next split `{hint.gap_next_path}`")
    return ", ".join(parts)


def markdown_lines_for_hint(hint: BoundaryHint) -> list[str]:
    lines: list[str] = []
    target = hint.suggested_path
    if hint.bucket and top_bucket(target) is None:
        target = f"{hint.bucket}/{target}"

    lines.append(f"- `{hint.retail_source_name}` -> `{target}`")
    if hint.alias_names:
        lines.append("  region aliases: " + ", ".join(f"`{name}`" for name in hint.alias_names))
    if hint.bundle_ids:
        lines.append("  bundles: " + ", ".join(f"`{bundle_id}`" for bundle_id in hint.bundle_ids))
    if hint.retail_labels:
        lines.append("  retail labels: " + ", ".join(f"`{label}`" for label in hint.retail_labels))
    if hint.retail_messages:
        lines.append("  retail messages: " + ", ".join(f"`{message}`" for message in hint.retail_messages[:3]))
    if hint.span_start is not None and hint.span_end is not None:
        lines.append(
            f"  EN span: `0x{hint.span_start:08X}-0x{hint.span_end:08X}` (`0x{hint.span_size:X}` bytes)"
        )
    else:
        lines.append("  EN span: none")
    if hint.en_xrefs:
        lines.append("  EN xrefs: " + ", ".join(f"`{xref}`" for xref in hint.en_xrefs[:6]))
    else:
        lines.append("  EN xrefs: none")
    if hint.xref_functions:
        lines.append(
            "  EN functions: " + ", ".join(f"`{format_symbol_span(function)}`" for function in hint.xref_functions[:6])
        )
    lines.append("  split status: " + describe_gap(hint))
    if hint.debug_paths:
        lines.append("  debug paths: " + ", ".join(f"`{path}`" for path in hint.debug_paths[:3]))
    if hint.reference_paths:
        lines.append("  reference paths: " + ", ".join(f"`{path}`" for path in hint.reference_paths[:3]))
    if hint.debug_named_functions:
        lines.append("  debug names: " + ", ".join(f"`{name}`" for name in hint.debug_named_functions[:6]))
    elif hint.reference_symbol_hints:
        lines.append("  reference names: " + ", ".join(f"`{name}`" for name in hint.reference_symbol_hints[:6]))
    if hint.nearby_before:
        lines.append("  nearby before: " + ", ".join(f"`{name}`" for name in hint.nearby_before))
    if hint.nearby_after:
        lines.append("  nearby after: " + ", ".join(f"`{name}`" for name in hint.nearby_after))
    return lines


def summary_markdown(hints: list[BoundaryHint], limit: int) -> str:
    xref_backed = [hint for hint in hints if hint.xref_count]
    unsplit = [hint for hint in xref_backed if hint.split_status == "unsplit"]
    with_targets = [hint for hint in hints if hint.suggested_path != Path(hint.retail_source_name).name]
    cross_region = [hint for hint in hints if len(hint.bundle_ids) >= 3]

    lines: list[str] = []
    lines.append("# Retail source-boundary hints")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Retail source groups scanned: `{len(hints)}`")
    lines.append(f"- Groups with EN xrefs: `{len(xref_backed)}`")
    lines.append(f"- EN xref groups still outside current `splits.txt`: `{len(unsplit)}`")
    lines.append(f"- Groups with a concrete path hint: `{len(with_targets)}`")
    lines.append(f"- Groups seen in at least three bundled regions: `{len(cross_region)}`")
    lines.append("")
    lines.append("## Highest-value unsplit boundary seeds")
    visible = [hint for hint in unsplit[:limit]]
    if visible:
        for hint in visible:
            lines.extend(markdown_lines_for_hint(hint))
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Lower-signal retail names")
    residual = [hint for hint in hints if hint not in visible]
    if residual:
        for hint in residual[: min(6, len(residual))]:
            lines.append(
                f"- `{hint.retail_source_name}`: `{hint.split_status}`, xrefs `{hint.xref_count}`, target `{hint.suggested_path}`"
            )
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_boundaries.py`")
    lines.append("- Search one source or path: `python tools/orig/source_boundaries.py --search objanim textblock camcontrol`")
    lines.append("- CSV dump: `python tools/orig/source_boundaries.py --format csv`")
    return "\n".join(lines)


def search_markdown(hints: list[BoundaryHint], patterns: list[str]) -> str:
    lowered = [pattern.lower() for pattern in patterns]
    matches: list[BoundaryHint] = []
    for hint in hints:
        fields = [
            hint.retail_source_name.lower(),
            hint.suggested_path.lower(),
            (hint.bucket or "").lower(),
            hint.split_status.lower(),
        ]
        fields.extend(name.lower() for name in hint.alias_names)
        fields.extend(name.lower() for name in hint.bundle_ids)
        fields.extend(name.lower() for name in hint.retail_labels)
        fields.extend(name.lower() for name in hint.retail_messages)
        fields.extend(name.lower() for name in hint.en_xrefs)
        fields.extend(function.name.lower() for function in hint.xref_functions)
        fields.extend(path.lower() for path in hint.debug_paths)
        fields.extend(path.lower() for path in hint.reference_paths)
        fields.extend(name.lower() for name in hint.debug_named_functions)
        fields.extend(name.lower() for name in hint.reference_symbol_hints)
        if any(any(pattern in field for field in fields) for pattern in lowered):
            matches.append(hint)

    lines = ["# Retail source-boundary search", ""]
    if not matches:
        lines.append("- No matching boundary hints.")
        return "\n".join(lines)

    for hint in matches:
        lines.extend(markdown_lines_for_hint(hint))
    return "\n".join(lines)


def rows_to_csv(hints: list[BoundaryHint]) -> str:
    fieldnames = [
        "retail_source_name",
        "alias_names",
        "bundle_ids",
        "suggested_path",
        "bucket",
        "retail_labels",
        "retail_messages",
        "xref_count",
        "en_xrefs",
        "en_function_spans",
        "span_start",
        "span_end",
        "span_size",
        "split_status",
        "current_split_paths",
        "gap_start",
        "gap_end",
        "gap_prev_path",
        "gap_next_path",
        "debug_paths",
        "debug_named_functions",
        "reference_paths",
        "reference_symbol_hints",
        "nearby_before",
        "nearby_after",
        "score",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for hint in hints:
        writer.writerow(
            {
                "retail_source_name": hint.retail_source_name,
                "alias_names": ",".join(hint.alias_names),
                "bundle_ids": ",".join(hint.bundle_ids),
                "suggested_path": hint.suggested_path,
                "bucket": hint.bucket or "",
                "retail_labels": ",".join(hint.retail_labels),
                "retail_messages": ",".join(hint.retail_messages),
                "xref_count": hint.xref_count,
                "en_xrefs": ",".join(hint.en_xrefs),
                "en_function_spans": ",".join(format_symbol_span(function) for function in hint.xref_functions),
                "span_start": "" if hint.span_start is None else f"0x{hint.span_start:08X}",
                "span_end": "" if hint.span_end is None else f"0x{hint.span_end:08X}",
                "span_size": "" if hint.span_size is None else f"0x{hint.span_size:X}",
                "split_status": hint.split_status,
                "current_split_paths": ",".join(hint.current_split_paths),
                "gap_start": "" if hint.gap_start is None else f"0x{hint.gap_start:08X}",
                "gap_end": "" if hint.gap_end is None else f"0x{hint.gap_end:08X}",
                "gap_prev_path": hint.gap_prev_path or "",
                "gap_next_path": hint.gap_next_path or "",
                "debug_paths": ",".join(hint.debug_paths),
                "debug_named_functions": ",".join(hint.debug_named_functions),
                "reference_paths": ",".join(hint.reference_paths),
                "reference_symbol_hints": ",".join(hint.reference_symbol_hints),
                "nearby_before": ",".join(hint.nearby_before),
                "nearby_after": ",".join(hint.nearby_after),
                "score": hint.score,
            }
        )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crosswalk retail source-tag evidence to current EN text gaps and split-boundary hints."
    )
    parser.add_argument("--dol", type=Path, default=Path("orig/GSAE01/sys/main.dol"), help="Path to the retail EN main.dol.")
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"), help="Current EN symbols.txt.")
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"), help="Current EN splits.txt.")
    parser.add_argument("--debug-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Debug-side symbols used for the retail source crosswalk.")
    parser.add_argument("--debug-splits", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"), help="Debug-side splits used for the retail source crosswalk.")
    parser.add_argument("--debug-srcfiles", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Debug-side source inventory used for the retail source crosswalk.")
    parser.add_argument("--reference-configure", type=Path, default=Path("reference_projects/rena-tools/sfadebug/configure.py"), help="Reference configure.py mined only for side-path hints.")
    parser.add_argument("--reference-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Reference symbols mined only for side-function hints.")
    parser.add_argument("--reference-inventory", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Reference source inventory mined only for neighbor context.")
    parser.add_argument("--reference-dll-registry", type=Path, default=Path("reference_projects/rena-tools/StarFoxAdventures/data/KD/dlls.xml"), help="Reference DLL registry mined only for side DLL/srcfile hints.")
    parser.add_argument("--reference-object-xml", type=Path, nargs="*", default=(Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects.xml"), Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects2.xml")), help="Reference object XML files mined only for descriptive hits.")
    parser.add_argument("--search", nargs="+", help="Case-insensitive substring search across source names, xrefs, paths, and neighboring symbols.")
    parser.add_argument("--format", choices=("markdown", "csv"), default="markdown", help="Output format.")
    parser.add_argument("--limit", type=int, default=8, help="Maximum boundary seeds to show in summary mode.")
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    groups = build_groups(
        dol=args.dol,
        symbols=args.symbols,
        debug_symbols=args.debug_symbols,
        debug_splits=args.debug_splits,
        debug_srcfiles=args.debug_srcfiles,
    )
    reference_hints = collect_reference_hints(
        groups=groups,
        reference_configure=args.reference_configure,
        reference_symbols=args.reference_symbols,
        reference_inventory=args.reference_inventory,
        reference_dll_registry=args.reference_dll_registry,
        reference_object_xmls=tuple(args.reference_object_xml),
    )
    current_functions = load_function_symbols(args.symbols)
    current_splits = build_split_ranges(args.splits)
    hints = build_boundary_hints(groups, reference_hints, current_functions, current_splits)

    if args.format == "csv":
        print(rows_to_csv(hints), end="")
        return
    if args.search:
        print(search_markdown(hints, args.search))
        return
    print(summary_markdown(hints, args.limit))


if __name__ == "__main__":
    main()
