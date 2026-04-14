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
from tools.orig.source_boundaries import (
    BoundaryHint,
    build_boundary_hints,
    build_split_ranges,
    describe_gap as describe_boundary_gap,
    format_symbol_span,
    split_gap_context,
)
from tools.orig.source_reference_hints import build_groups, collect_reference_hints


@dataclass(frozen=True)
class IslandMember:
    hint: BoundaryHint
    function_start_index: int
    function_end_index: int

    @property
    def span_start(self) -> int:
        assert self.hint.span_start is not None
        return self.hint.span_start

    @property
    def span_end(self) -> int:
        assert self.hint.span_end is not None
        return self.hint.span_end


@dataclass(frozen=True)
class SourceIsland:
    span_start: int
    span_end: int
    function_start_index: int
    function_end_index: int
    members: tuple[IslandMember, ...]
    total_xrefs: int
    split_status: str
    current_split_paths: tuple[str, ...]
    gap_start: int | None
    gap_end: int | None
    gap_prev_path: str | None
    gap_next_path: str | None
    neighboring_before: tuple[FunctionSymbol, ...]
    neighboring_after: tuple[FunctionSymbol, ...]
    uncovered_functions: tuple[FunctionSymbol, ...]

    @property
    def span_size(self) -> int:
        return self.span_end - self.span_start

    @property
    def member_count(self) -> int:
        return len(self.members)

    @property
    def touched_function_count(self) -> int:
        return self.function_end_index - self.function_start_index + 1

    @property
    def retail_function_count(self) -> int:
        addresses = {
            function.address
            for member in self.members
            for function in member.hint.xref_functions
        }
        return len(addresses)

    @property
    def source_names(self) -> tuple[str, ...]:
        return tuple(member.hint.retail_source_name for member in self.members)


def build_island_members(hints: list[BoundaryHint], current_functions: list[FunctionSymbol]) -> list[IslandMember]:
    index_by_address = {
        function.address: index
        for index, function in enumerate(current_functions)
    }
    members: list[IslandMember] = []
    for hint in hints:
        if hint.xref_count == 0 or not hint.xref_functions or hint.span_start is None or hint.span_end is None:
            continue
        start_index = min(index_by_address[function.address] for function in hint.xref_functions)
        end_index = max(index_by_address[function.address] for function in hint.xref_functions)
        members.append(
            IslandMember(
                hint=hint,
                function_start_index=start_index,
                function_end_index=end_index,
            )
        )
    members.sort(
        key=lambda item: (
            item.span_start,
            item.span_end,
            item.hint.retail_source_name.lower(),
        )
    )
    return members


def island_neighbors(
    current_functions: list[FunctionSymbol],
    start_index: int,
    end_index: int,
    radius: int = 3,
) -> tuple[tuple[FunctionSymbol, ...], tuple[FunctionSymbol, ...]]:
    before = tuple(current_functions[max(0, start_index - radius):start_index])
    after = tuple(current_functions[end_index + 1: min(len(current_functions), end_index + 1 + radius)])
    return before, after


def island_uncovered_functions(
    current_functions: list[FunctionSymbol],
    members: tuple[IslandMember, ...],
    start_index: int,
    end_index: int,
) -> tuple[FunctionSymbol, ...]:
    covered = {
        function.address
        for member in members
        for function in member.hint.xref_functions
    }
    values = [
        function
        for function in current_functions[start_index:end_index + 1]
        if function.address not in covered
    ]
    return tuple(values)


def make_island(
    members: list[IslandMember],
    current_functions: list[FunctionSymbol],
    split_ranges,
) -> SourceIsland:
    island_members = tuple(
        sorted(
            members,
            key=lambda item: (
                item.span_start,
                item.span_end,
                item.hint.retail_source_name.lower(),
            ),
        )
    )
    span_start = min(member.span_start for member in island_members)
    span_end = max(member.span_end for member in island_members)
    function_start_index = min(member.function_start_index for member in island_members)
    function_end_index = max(member.function_end_index for member in island_members)
    before, after = island_neighbors(current_functions, function_start_index, function_end_index)
    split_status, current_split_paths, gap_start, gap_end, gap_prev_path, gap_next_path = split_gap_context(
        split_ranges,
        span_start,
        span_end,
    )
    return SourceIsland(
        span_start=span_start,
        span_end=span_end,
        function_start_index=function_start_index,
        function_end_index=function_end_index,
        members=island_members,
        total_xrefs=sum(member.hint.xref_count for member in island_members),
        split_status=split_status,
        current_split_paths=current_split_paths,
        gap_start=gap_start,
        gap_end=gap_end,
        gap_prev_path=gap_prev_path,
        gap_next_path=gap_next_path,
        neighboring_before=before,
        neighboring_after=after,
        uncovered_functions=island_uncovered_functions(
            current_functions,
            island_members,
            function_start_index,
            function_end_index,
        ),
    )


def should_merge(
    island_members: list[IslandMember],
    candidate: IslandMember,
    max_gap_bytes: int,
    max_gap_functions: int,
) -> bool:
    island_span_end = max(member.span_end for member in island_members)
    island_function_end = max(member.function_end_index for member in island_members)
    byte_gap = candidate.span_start - island_span_end
    function_gap = candidate.function_start_index - island_function_end - 1
    if byte_gap <= 0:
        return True
    return byte_gap <= max_gap_bytes and function_gap <= max_gap_functions


def build_islands(
    hints: list[BoundaryHint],
    current_functions: list[FunctionSymbol],
    split_ranges,
    max_gap_bytes: int,
    max_gap_functions: int,
) -> list[SourceIsland]:
    members = build_island_members(hints, current_functions)
    if not members:
        return []

    islands: list[SourceIsland] = []
    current: list[IslandMember] = [members[0]]
    for member in members[1:]:
        if should_merge(current, member, max_gap_bytes, max_gap_functions):
            current.append(member)
            continue
        islands.append(make_island(current, current_functions, split_ranges))
        current = [member]
    islands.append(make_island(current, current_functions, split_ranges))
    islands.sort(key=lambda item: item.span_start)
    return islands


def island_score(island: SourceIsland) -> int:
    score = island.total_xrefs * 300
    score += island.member_count * 180
    score += island.retail_function_count * 120
    score += min(island.span_size, 0x8000) // 16
    score += min(island.touched_function_count, 12) * 20
    if island.member_count > 1:
        score += 400
    if island.split_status == "unsplit":
        score += 200
    return score


def format_member_summary(member: IslandMember) -> str:
    path_text = member.hint.suggested_path
    label_text = ""
    if member.hint.retail_labels:
        label_text = " labels=" + ",".join(member.hint.retail_labels[:3])
    return (
        f"`{member.hint.retail_source_name}` -> `{path_text}` "
        f"span=`0x{member.span_start:08X}-0x{member.span_end:08X}` "
        f"xrefs=`{member.hint.xref_count}`{label_text}"
    )


def summarize_uncovered(functions: tuple[FunctionSymbol, ...], limit: int = 6) -> str:
    if not functions:
        return "none"
    preview = ", ".join(f"`{format_symbol_span(function)}`" for function in functions[:limit])
    if len(functions) > limit:
        preview += f", ... (+{len(functions) - limit} more)"
    return preview


def format_island_title(island: SourceIsland) -> str:
    if island.member_count == 1:
        return island.members[0].hint.retail_source_name
    return " + ".join(member.hint.retail_source_name for member in island.members)


def summary_markdown(islands: list[SourceIsland], limit: int) -> str:
    ranked = sorted(
        islands,
        key=lambda item: (-island_score(item), item.span_start),
    )
    multi_source = [island for island in islands if island.member_count > 1]
    unsplit = [island for island in islands if island.split_status == "unsplit"]

    lines: list[str] = []
    lines.append("# Retail source skeleton")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Xref-backed retail source groups: `{sum(island.member_count for island in islands)}`")
    lines.append(f"- EN text islands from those groups: `{len(islands)}`")
    lines.append(f"- Multi-source islands: `{len(multi_source)}`")
    lines.append(f"- Islands still outside current `splits.txt`: `{len(unsplit)}`")
    lines.append("")
    lines.append("## Highest-leverage islands")
    for island in ranked[:limit]:
        lines.append(
            f"- `{format_island_title(island)}` "
            f"span=`0x{island.span_start:08X}-0x{island.span_end:08X}` "
            f"size=`0x{island.span_size:X}` functions=`{island.touched_function_count}` "
            f"retail_functions=`{island.retail_function_count}` xrefs=`{island.total_xrefs}`"
        )
        lines.append("  split status: " + describe_gap(island))
        lines.append("  sources: " + "; ".join(format_member_summary(member) for member in island.members))
        lines.append("  uncovered functions: " + summarize_uncovered(island.uncovered_functions))
        if island.neighboring_before:
            lines.append(
                "  nearby before: "
                + ", ".join(f"`{format_symbol_span(function)}`" for function in island.neighboring_before)
            )
        if island.neighboring_after:
            lines.append(
                "  nearby after: "
                + ", ".join(f"`{format_symbol_span(function)}`" for function in island.neighboring_after)
            )
    lines.append("")
    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_skeleton.py`")
    lines.append("- Search one island, source, or address: `python tools/orig/source_skeleton.py --search textblock laser 0x802096`")
    lines.append("- CSV dump: `python tools/orig/source_skeleton.py --format csv`")
    return "\n".join(lines)


def detailed_markdown(islands: list[SourceIsland]) -> str:
    lines: list[str] = ["# Retail source skeleton search", ""]
    if not islands:
        lines.append("- No matching islands.")
        return "\n".join(lines)

    for island in islands:
        lines.append(
            f"## `{format_island_title(island)}`"
        )
        lines.append(
            f"- span=`0x{island.span_start:08X}-0x{island.span_end:08X}` size=`0x{island.span_size:X}` "
            f"functions=`{island.touched_function_count}` retail_functions=`{island.retail_function_count}` xrefs=`{island.total_xrefs}`"
        )
        lines.append("- split status: " + describe_gap(island))
        lines.append("- retail-backed sources:")
        for member in island.members:
            lines.append(
                f"  - `{member.hint.retail_source_name}` -> `{member.hint.suggested_path}` "
                f"span=`0x{member.span_start:08X}-0x{member.span_end:08X}` xrefs=`{member.hint.xref_count}`"
            )
            if member.hint.retail_labels:
                lines.append("    labels: " + ", ".join(f"`{label}`" for label in member.hint.retail_labels))
            if member.hint.retail_messages:
                lines.append(
                    "    messages: " + ", ".join(f"`{message}`" for message in member.hint.retail_messages[:4])
                )
            if member.hint.en_xrefs:
                lines.append("    EN xrefs: " + ", ".join(f"`{xref}`" for xref in member.hint.en_xrefs[:8]))
            if member.hint.debug_paths:
                lines.append("    debug paths: " + ", ".join(f"`{path}`" for path in member.hint.debug_paths[:3]))
            if member.hint.reference_paths:
                lines.append("    reference paths: " + ", ".join(f"`{path}`" for path in member.hint.reference_paths[:3]))
        if island.uncovered_functions:
            lines.append("- uncovered current EN functions:")
            for function in island.uncovered_functions[:12]:
                lines.append(f"  - `{format_symbol_span(function)}`")
        else:
            lines.append("- uncovered current EN functions: none")
        if island.neighboring_before:
            lines.append(
                "- nearby before: "
                + ", ".join(f"`{format_symbol_span(function)}`" for function in island.neighboring_before)
            )
        if island.neighboring_after:
            lines.append(
                "- nearby after: "
                + ", ".join(f"`{format_symbol_span(function)}`" for function in island.neighboring_after)
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def island_matches(island: SourceIsland, patterns: list[str]) -> bool:
    fields = [
        format_island_title(island).lower(),
        f"0x{island.span_start:08x}",
        f"0x{island.span_end:08x}",
        island.split_status.lower(),
    ]
    fields.extend(member.hint.retail_source_name.lower() for member in island.members)
    fields.extend(member.hint.suggested_path.lower() for member in island.members)
    fields.extend(label.lower() for member in island.members for label in member.hint.retail_labels)
    fields.extend(message.lower() for member in island.members for message in member.hint.retail_messages)
    fields.extend(xref.lower() for member in island.members for xref in member.hint.en_xrefs)
    fields.extend(function.name.lower() for function in island.uncovered_functions)
    fields.extend(function.name.lower() for function in island.neighboring_before)
    fields.extend(function.name.lower() for function in island.neighboring_after)
    lowered = [pattern.lower() for pattern in patterns]
    return any(any(pattern in field for field in fields) for pattern in lowered)


def rows_to_csv(islands: list[SourceIsland]) -> str:
    fieldnames = [
        "span_start",
        "span_end",
        "span_size",
        "touched_function_count",
        "retail_function_count",
        "member_count",
        "total_xrefs",
        "split_status",
        "current_split_paths",
        "gap_start",
        "gap_end",
        "gap_prev_path",
        "gap_next_path",
        "source_names",
        "suggested_paths",
        "retail_labels",
        "retail_messages",
        "en_xrefs",
        "uncovered_functions",
        "neighboring_before",
        "neighboring_after",
        "score",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for island in islands:
        writer.writerow(
            {
                "span_start": f"0x{island.span_start:08X}",
                "span_end": f"0x{island.span_end:08X}",
                "span_size": f"0x{island.span_size:X}",
                "touched_function_count": island.touched_function_count,
                "retail_function_count": island.retail_function_count,
                "member_count": island.member_count,
                "total_xrefs": island.total_xrefs,
                "split_status": island.split_status,
                "current_split_paths": ",".join(island.current_split_paths),
                "gap_start": "" if island.gap_start is None else f"0x{island.gap_start:08X}",
                "gap_end": "" if island.gap_end is None else f"0x{island.gap_end:08X}",
                "gap_prev_path": island.gap_prev_path or "",
                "gap_next_path": island.gap_next_path or "",
                "source_names": ",".join(island.source_names),
                "suggested_paths": ",".join(member.hint.suggested_path for member in island.members),
                "retail_labels": ",".join(label for member in island.members for label in member.hint.retail_labels),
                "retail_messages": ",".join(
                    message for member in island.members for message in member.hint.retail_messages
                ),
                "en_xrefs": ",".join(xref for member in island.members for xref in member.hint.en_xrefs),
                "uncovered_functions": ",".join(format_symbol_span(function) for function in island.uncovered_functions),
                "neighboring_before": ",".join(format_symbol_span(function) for function in island.neighboring_before),
                "neighboring_after": ",".join(format_symbol_span(function) for function in island.neighboring_after),
                "score": island_score(island),
            }
        )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Group retail EN source-tag xrefs into address-ordered source skeleton islands."
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
    parser.add_argument("--max-gap-bytes", type=lambda value: int(value, 0), default=0x180, help="Maximum byte gap between member spans before a new island is started.")
    parser.add_argument("--max-gap-functions", type=int, default=2, help="Maximum uncovered functions between member spans before a new island is started.")
    parser.add_argument("--search", nargs="+", help="Case-insensitive substring search across source names, paths, xrefs, and addresses.")
    parser.add_argument("--format", choices=("markdown", "csv"), default="markdown", help="Output format.")
    parser.add_argument("--limit", type=int, default=8, help="Maximum islands to show in summary mode.")
    return parser


def describe_gap(island: SourceIsland) -> str:
    return describe_gap_from_fields(
        split_status=island.split_status,
        current_split_paths=island.current_split_paths,
        gap_start=island.gap_start,
        gap_end=island.gap_end,
        gap_prev_path=island.gap_prev_path,
        gap_next_path=island.gap_next_path,
    )


def describe_gap_from_fields(
    split_status: str,
    current_split_paths: tuple[str, ...],
    gap_start: int | None,
    gap_end: int | None,
    gap_prev_path: str | None,
    gap_next_path: str | None,
) -> str:
    dummy = type(
        "GapHint",
        (),
        {
            "split_status": split_status,
            "current_split_paths": current_split_paths,
            "gap_start": gap_start,
            "gap_end": gap_end,
            "gap_prev_path": gap_prev_path,
            "gap_next_path": gap_next_path,
        },
    )
    return describe_boundary_gap(dummy)  # type: ignore[arg-type]


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
    split_ranges = build_split_ranges(args.splits)
    boundary_hints = build_boundary_hints(
        groups,
        reference_hints,
        current_functions,
        split_ranges,
        args.dol,
    )
    islands = build_islands(
        boundary_hints,
        current_functions,
        split_ranges,
        max_gap_bytes=args.max_gap_bytes,
        max_gap_functions=args.max_gap_functions,
    )

    visible = islands if not args.search else [island for island in islands if island_matches(island, args.search)]

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(visible))
        elif args.search:
            sys.stdout.write(detailed_markdown(visible))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(visible, args.limit))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
