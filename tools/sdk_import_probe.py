from __future__ import annotations

import argparse
import re
import shlex
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dolphin_sdk_symbols import (
    ConfigSymbol,
    build_candidates,
    build_translated_symbols,
    cluster_source_candidates,
    default_dolphin_path,
    is_actionable,
    load_config_symbols,
    load_dolphin_symbols,
    load_splits,
    source_match_names,
)


BUILD_LINE_RE = re.compile(
    r"^build build\\(?P<version>[^\\]+)\\src\\base\\PPCArch\.o: \S+ "
    r"src\\base\\PPCArch\.c(?:\s+\|.*)?$"
)
NAME_RE = re.compile(r"^\s+Name: (?P<name>.*?)(?: \(\d+\))?$")
SIZE_RE = re.compile(r"^\s+Size: (?P<size>0x[0-9A-Fa-f]+|\d+)$")
VALUE_RE = re.compile(r"^\s+Value: (?P<value>0x[0-9A-Fa-f]+|\d+)$")
SECTION_RE = re.compile(r"^\s+Section: (?P<section>.+?) \(")
TYPE_RE = re.compile(r"^\s+Type: (?P<type>.+?) \(")
SYMBOL_START_RE = re.compile(r"^\s*Symbol \{$")
SECTION_START_RE = re.compile(r"^\s*Section \{$")
QUOTED_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"(?P<path>[^"]+)"')


@dataclass(frozen=True)
class BuildConfig:
    mw_version: str
    cflags: tuple[str, ...]


@dataclass(frozen=True)
class ObjectSection:
    name: str
    size: int


@dataclass(frozen=True)
class ObjectSymbol:
    name: str
    value: int
    size: int
    section: str
    type_name: str


@dataclass(frozen=True)
class AnchorCandidate:
    compiled_symbol: ObjectSymbol
    config_address: int
    predicted_start: int
    size_matches: bool


@dataclass(frozen=True)
class StartHypothesis:
    start: int
    anchors: tuple[AnchorCandidate, ...]

    @property
    def exact_count(self) -> int:
        return sum(anchor.size_matches for anchor in self.anchors)


@dataclass(frozen=True)
class SourceReport:
    source: Path
    sections: tuple[ObjectSection, ...]
    compiled_functions: tuple[ObjectSymbol, ...]
    text_size: int
    anchors: tuple[AnchorCandidate, ...]
    hypotheses: tuple[StartHypothesis, ...]
    translated_clusters: tuple["TranslatedCluster", ...] = ()


@dataclass(frozen=True)
class TranslatedCluster:
    start: int
    end: int
    span: int
    score: int
    match_count: int
    unique_name_count: int
    exact_name_count: int
    active_count: int
    text_overrun: int
    names: tuple[str, ...]


@dataclass(frozen=True)
class BoundaryConflict:
    boundary: str
    symbol_name: str
    symbol_start: int
    symbol_end: int


def parse_build_config(build_ninja: Path, version: str) -> BuildConfig:
    lines = build_ninja.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        match = BUILD_LINE_RE.match(line)
        if match is None or match.group("version") != version:
            continue

        mw_version = ""
        cflags_parts: list[str] = []
        cursor = index + 1
        while cursor < len(lines) and lines[cursor].startswith("  "):
            entry = lines[cursor]
            if entry.startswith("  mw_version = "):
                mw_version = entry.split("=", 1)[1].strip()
            elif entry.startswith("  cflags = "):
                value = entry.split("=", 1)[1].strip()
                cflags_parts.append(value.removesuffix("$").strip())
                cursor += 1
                while cursor < len(lines) and lines[cursor].startswith("      "):
                    continuation = lines[cursor].strip()
                    cflags_parts.append(continuation.removesuffix("$").strip())
                    cursor += 1
                continue
            cursor += 1

        if not mw_version or not cflags_parts:
            break
        cflags = tuple(shlex.split(" ".join(cflags_parts), posix=True))
        return BuildConfig(mw_version=mw_version, cflags=cflags)

    raise SystemExit(f"Unable to locate Dolphin C build flags for {version} in {build_ninja}")


def compile_source(
    source: Path,
    build_config: BuildConfig,
    version: str,
    output_root: Path,
    extra_include_dirs: tuple[Path, ...] = (),
) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    compiler = Path("build") / "compilers" / build_config.mw_version / "mwcceppc.exe"
    sjiswrap = Path("build") / "tools" / "sjiswrap.exe"
    if not compiler.is_file():
        raise SystemExit(f"Missing compiler: {compiler}")
    if not sjiswrap.is_file():
        raise SystemExit(f"Missing sjiswrap: {sjiswrap}")

    compile_args = [
        str(sjiswrap),
        str(compiler),
        *build_config.cflags,
        *(
            arg
            for include_dir in extra_include_dirs
            for arg in ("-i", str(include_dir).replace("/", "\\"))
        ),
        "-MMD",
        "-c",
        str(source).replace("/", "\\"),
        "-o",
        str(output_root).replace("/", "\\"),
    ]
    subprocess.run(compile_args, check=True)

    object_path = output_root / f"{source.stem}.o"
    if not object_path.is_file():
        raise SystemExit(f"Expected compiled object not found: {object_path}")
    return object_path


def resolve_extra_include_dirs(
    source: Path,
    explicit_include_dirs: tuple[Path, ...],
) -> tuple[Path, ...]:
    resolved: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        try:
            normalized = path.resolve()
        except OSError:
            normalized = path
        if normalized in seen or not path.is_dir():
            return
        seen.add(normalized)
        resolved.append(path)

    for include_dir in explicit_include_dirs:
        add(include_dir)

    add(source.parent)

    include_root = Path("include")
    search_root = include_root if include_root.is_dir() else None
    if search_root is None:
        return tuple(resolved)

    for raw_line in source.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = QUOTED_INCLUDE_RE.match(raw_line)
        if match is None:
            continue

        include_name = match.group("path")
        if "/" in include_name or "\\" in include_name:
            continue

        matches = list(search_root.rglob(include_name))
        if len(matches) != 1:
            continue
        add(matches[0].parent)

    return tuple(resolved)


def parse_llvm_readobj(object_path: Path) -> tuple[list[ObjectSection], list[ObjectSymbol]]:
    llvm_readobj = shutil.which("llvm-readobj")
    if llvm_readobj is None:
        llvm_readobj = shutil.which("llvm-readobj.exe")
    if llvm_readobj is None:
        raise SystemExit("Missing llvm-readobj in PATH")

    result = subprocess.run(
        [llvm_readobj, "--sections", "--symbols", str(object_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    lines = result.stdout.splitlines()

    sections: list[ObjectSection] = []
    symbols: list[ObjectSymbol] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if SECTION_START_RE.match(line):
            name = ""
            size = 0
            index += 1
            while index < len(lines) and lines[index].strip() != "}":
                name_match = NAME_RE.match(lines[index])
                size_match = SIZE_RE.match(lines[index])
                if name_match:
                    name = name_match.group("name")
                elif size_match:
                    size = int(size_match.group("size"), 0)
                index += 1
            if name:
                sections.append(ObjectSection(name=name, size=size))
        elif SYMBOL_START_RE.match(line):
            name = ""
            value = 0
            size = 0
            section = ""
            type_name = ""
            index += 1
            while index < len(lines) and lines[index].strip() != "}":
                name_match = NAME_RE.match(lines[index])
                value_match = VALUE_RE.match(lines[index])
                size_match = SIZE_RE.match(lines[index])
                section_match = SECTION_RE.match(lines[index])
                type_match = TYPE_RE.match(lines[index])
                if name_match:
                    name = name_match.group("name")
                elif value_match:
                    value = int(value_match.group("value"), 0)
                elif size_match:
                    size = int(size_match.group("size"), 0)
                elif section_match:
                    section = section_match.group("section")
                elif type_match:
                    type_name = type_match.group("type")
                index += 1
            if name:
                symbols.append(
                    ObjectSymbol(
                        name=name,
                        value=value,
                        size=size,
                        section=section,
                        type_name=type_name,
                    )
                )
        index += 1

    return sections, symbols


def find_anchor_candidates(
    compiled_symbols: list[ObjectSymbol],
    config_symbols_path: Path,
) -> list[AnchorCandidate]:
    config_symbols = load_config_symbols(config_symbols_path)
    by_name: dict[str, list] = {}
    for symbol in config_symbols:
        if symbol.section != ".text":
            continue
        by_name.setdefault(symbol.name, []).append(symbol)

    candidates: list[AnchorCandidate] = []
    for symbol in compiled_symbols:
        if symbol.type_name != "Function" or symbol.section != ".text":
            continue
        matches = by_name.get(symbol.name)
        if not matches or len(matches) != 1:
            continue
        config_symbol = matches[0]
        candidates.append(
            AnchorCandidate(
                compiled_symbol=symbol,
                config_address=config_symbol.address,
                predicted_start=config_symbol.address - symbol.value,
                size_matches=config_symbol.size == symbol.size,
            )
        )
    return candidates


def describe_overlap(version: str, start: int, end: int) -> list[str]:
    splits_path = Path("config") / version / "splits.txt"
    overlaps: list[str] = []
    for split in load_splits(splits_path):
        if split.section != ".text":
            continue
        if split.end <= start or split.start >= end:
            continue
        overlaps.append(f"{split.path}@0x{split.start:08X}-0x{split.end:08X}")
    return overlaps


@lru_cache(maxsize=None)
def load_text_symbols(version: str) -> tuple[ConfigSymbol, ...]:
    symbols_path = Path("config") / version / "symbols.txt"
    return tuple(
        sorted(
            (
                symbol
                for symbol in load_config_symbols(symbols_path)
                if symbol.section == ".text" and symbol.size is not None
            ),
            key=lambda symbol: symbol.address,
        )
    )


def describe_boundary_conflicts(version: str, start: int, end: int) -> list[BoundaryConflict]:
    conflicts: list[BoundaryConflict] = []
    for symbol in load_text_symbols(version):
        symbol_end = symbol.address + symbol.size
        if symbol.address < start < symbol_end:
            conflicts.append(
                BoundaryConflict(
                    boundary="start",
                    symbol_name=symbol.name,
                    symbol_start=symbol.address,
                    symbol_end=symbol_end,
                )
            )
        if symbol.address < end < symbol_end:
            conflicts.append(
                BoundaryConflict(
                    boundary="end",
                    symbol_name=symbol.name,
                    symbol_start=symbol.address,
                    symbol_end=symbol_end,
                )
            )
    return conflicts


def find_exact_text_symbol(version: str, address: int) -> ConfigSymbol | None:
    for symbol in load_text_symbols(version):
        if symbol.address == address:
            return symbol
    return None


def find_covering_text_symbol(version: str, address: int) -> ConfigSymbol | None:
    for symbol in load_text_symbols(version):
        symbol_end = symbol.address + symbol.size
        if symbol.address <= address < symbol_end:
            return symbol
    return None


def build_start_hypotheses(anchors: list[AnchorCandidate]) -> list[StartHypothesis]:
    by_start: dict[int, list[AnchorCandidate]] = {}
    for anchor in anchors:
        by_start.setdefault(anchor.predicted_start, []).append(anchor)

    hypotheses = [
        StartHypothesis(
            start=start,
            anchors=tuple(sorted(group, key=lambda item: item.compiled_symbol.value)),
        )
        for start, group in by_start.items()
    ]
    hypotheses.sort(
        key=lambda item: (
            -len(item.anchors),
            -item.exact_count,
            item.start,
        )
    )
    return hypotheses


def analyze_source(
    version: str,
    config_symbols_path: Path,
    source: Path,
    build_config: BuildConfig,
    output_root: Path,
    extra_include_dirs: tuple[Path, ...],
    translated_clusters: tuple[TranslatedCluster, ...],
) -> SourceReport:
    include_dirs = resolve_extra_include_dirs(source, extra_include_dirs)
    object_path = compile_source(
        source,
        build_config,
        version,
        output_root,
        extra_include_dirs=include_dirs,
    )
    sections, symbols = parse_llvm_readobj(object_path)
    anchors = find_anchor_candidates(symbols, config_symbols_path)
    compiled_functions = tuple(
        sorted(
            (
                symbol
                for symbol in symbols
                if symbol.type_name == "Function" and symbol.section == ".text"
            ),
            key=lambda symbol: symbol.value,
        )
    )
    text_size = next((section.size for section in sections if section.name == ".text"), 0)
    normalized_clusters = tuple(
        TranslatedCluster(
            start=cluster.start,
            end=cluster.end,
            span=cluster.span,
            score=cluster.score,
            match_count=cluster.match_count,
            unique_name_count=cluster.unique_name_count,
            exact_name_count=cluster.exact_name_count,
            active_count=cluster.active_count,
            text_overrun=max(0, text_size - cluster.span),
            names=cluster.names,
        )
        for cluster in translated_clusters
    )
    return SourceReport(
        source=source,
        sections=tuple(sections),
        compiled_functions=compiled_functions,
        text_size=text_size,
        anchors=tuple(anchors),
        hypotheses=tuple(build_start_hypotheses(anchors)),
        translated_clusters=normalized_clusters,
    )


def build_translated_clusters(
    version: str,
    source: Path,
    min_score: int,
    require_provenance: bool,
    gap: int,
) -> tuple[TranslatedCluster, ...]:
    dolphin_path = default_dolphin_path(version)
    config_dir = Path("config") / version
    symbols_path = config_dir / "symbols.txt"
    splits_path = config_dir / "splits.txt"
    src_root = Path("src")

    dolphin_symbols = load_dolphin_symbols(dolphin_path)
    config_symbols = load_config_symbols(symbols_path)
    split_ranges = load_splits(splits_path)
    translated_symbols = build_translated_symbols(
        dolphin_symbols,
        config_symbols,
        split_ranges,
        manual_delta=None,
    )
    candidates = build_candidates(translated_symbols)

    seed_keys = {
        (candidate.symbol.section, candidate.translated_address)
        for candidate in candidates
        if candidate.symbol.section == ".text"
        and candidate.translation_delta is not None
        and (
            (candidate.exact is not None and not candidate.exact.name.startswith(("fn_", "FUN_", "lbl_", "sub_", "zz_")))
            or is_actionable(candidate, min_score, True, require_provenance)
        )
        and (
            not require_provenance
            or (candidate.symbol.library and candidate.symbol.object_path)
        )
    }

    seed_index: dict[str, list] = defaultdict(list)
    all_index: dict[str, list] = defaultdict(list)
    for item in translated_symbols:
        if item.symbol.section != ".text" or item.translation_delta is None:
            continue

        names = source_match_names(item.symbol, item.exact)
        if not names:
            continue

        for name in names:
            all_index[name].append(item)
            key = (item.symbol.section, item.translated_address)
            if key in seed_keys:
                seed_index[name].append(item)

    reports = cluster_source_candidates(
        source,
        src_root,
        seed_index,
        all_index,
        gap,
        require_provenance,
    )
    deduped: list[TranslatedCluster] = []
    seen: set[tuple[int, int, tuple[str, ...]]] = set()
    for report in reports:
        names = tuple(
            candidate.exact.name
            if candidate.exact is not None and not candidate.exact.name.startswith(("fn_", "FUN_", "lbl_", "sub_", "zz_"))
            else candidate.symbol.name
            for candidate in report.candidates[:6]
        )
        key = (report.start, report.end, names)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(
            TranslatedCluster(
                start=report.start,
                end=report.end,
                span=report.span,
                score=report.score,
                match_count=len(report.candidates),
                unique_name_count=report.unique_name_count,
                exact_name_count=report.exact_name_count,
                active_count=report.active_count,
                text_overrun=0,
                names=names,
            )
        )
    return tuple(deduped)


def print_report(
    version: str,
    report: SourceReport,
    hypothesis_limit: int,
    cluster_limit: int,
    show_functions: bool,
    function_limit: int,
) -> None:
    print(f"# {report.source.as_posix()}")
    print("sections:")
    for section in report.sections:
        if section.name.startswith(".rela") or section.name in {".symtab", ".strtab", ".shstrtab", ".comment"}:
            continue
        print(f"  {section.name:<8} 0x{section.size:X}")

    if report.translated_clusters:
        print("translated clusters:")
        for cluster in report.translated_clusters[:cluster_limit]:
            print(
                f"  0x{cluster.start:08X}-0x{cluster.end:08X} span=0x{cluster.span:X} "
                f"matches={cluster.match_count} exact={cluster.exact_name_count} "
                f"active={cluster.active_count} score={cluster.score} "
                f"overrun=0x{cluster.text_overrun:X}"
            )
            if cluster.names:
                print(f"    names={', '.join(cluster.names)}")

    if not report.anchors:
        print("anchors: none")
        print()
        return

    print("start hypotheses:")
    for hypothesis in report.hypotheses[:hypothesis_limit]:
        span_end = hypothesis.start + report.text_size
        overlaps = describe_overlap(version, hypothesis.start, span_end)
        boundary_conflicts = describe_boundary_conflicts(version, hypothesis.start, span_end)
        print(
            f"  0x{hypothesis.start:08X}-0x{span_end:08X} size=0x{report.text_size:X} "
            f"anchors={len(hypothesis.anchors)} exact-size={hypothesis.exact_count} "
            f"overlaps={len(overlaps)} boundary-conflicts={len(boundary_conflicts)}"
        )
        if overlaps:
            for overlap in overlaps[:5]:
                print(f"    {overlap}")
            if len(overlaps) > 5:
                print(f"    ... {len(overlaps) - 5} more")
        if boundary_conflicts:
            for conflict in boundary_conflicts[:4]:
                print(
                    f"    {conflict.boundary} inside {conflict.symbol_name}"
                    f"@0x{conflict.symbol_start:08X}-0x{conflict.symbol_end:08X}"
                )
            if len(boundary_conflicts) > 4:
                print(f"    ... {len(boundary_conflicts) - 4} more boundary conflicts")

        print("  anchor details:")
        for anchor in hypothesis.anchors:
            symbol = anchor.compiled_symbol
            exact_text = "yes" if anchor.size_matches else "no"
            print(
                f"    +0x{symbol.value:04X} {symbol.name:<28} "
                f"size=0x{symbol.size:X} addr=0x{anchor.config_address:08X} size-match={exact_text}"
            )
        if show_functions:
            print("  projected functions:")
            projected_functions = report.compiled_functions
            if function_limit > 0:
                projected_functions = projected_functions[:function_limit]
            for symbol in projected_functions:
                address = hypothesis.start + symbol.value
                exact = find_exact_text_symbol(version, address)
                cover = find_covering_text_symbol(version, address)
                status = "free"
                if exact is not None:
                    size_text = "yes" if exact.size == symbol.size else "no"
                    status = f"start:{exact.name},size-match:{size_text}"
                elif cover is not None:
                    offset = address - cover.address
                    status = (
                        f"inside:{cover.name}"
                        f"@+0x{offset:X}/0x{cover.size:X}"
                    )
                print(
                    f"    +0x{symbol.value:04X} 0x{address:08X} "
                    f"size=0x{symbol.size:X} {symbol.name} [{status}]"
                )
    print()


def print_ranked_summary(version: str, reports: list[SourceReport]) -> None:
    ranked: list[tuple[int, int, int, int, int, SourceReport, StartHypothesis | None]] = []
    for report in reports:
        best = report.hypotheses[0] if report.hypotheses else None
        overlap_count = 9999
        boundary_conflict_count = 9999
        if best is not None:
            overlap_count = len(describe_overlap(version, best.start, best.start + report.text_size))
            boundary_conflict_count = len(
                describe_boundary_conflicts(version, best.start, best.start + report.text_size)
            )
        ranked.append(
            (
                len(best.anchors) if best is not None else 0,
                best.exact_count if best is not None else 0,
                -boundary_conflict_count,
                -overlap_count,
                report.text_size,
                report,
                best,
            )
        )

    ranked.sort(
        key=lambda item: (
            -item[0],
            -item[1],
            item[2],
            item[3],
            -item[4],
            item[5].source.as_posix(),
        )
    )

    for anchor_count, exact_count, neg_boundary_conflict_count, neg_overlap_count, _, report, best in ranked:
        if best is None:
            print(
                f"anchors=0 exact=0 blockers=0 overlaps=0 text=0x{report.text_size:X} "
                f"{report.source.as_posix()} -"
            )
            continue

        boundary_conflict_count = -neg_boundary_conflict_count
        overlap_count = -neg_overlap_count
        span_end = best.start + report.text_size
        names = ", ".join(anchor.compiled_symbol.name for anchor in best.anchors[:5])
        print(
            f"anchors={anchor_count} exact={exact_count} blockers={boundary_conflict_count} "
            f"overlaps={overlap_count} "
            f"text=0x{report.text_size:X} {report.source.as_posix()} "
            f"0x{best.start:08X}-0x{span_end:08X}"
        )
        if names:
            print(f"  names={names}")
        if report.translated_clusters:
            cluster = report.translated_clusters[0]
            print(
                f"  translated=0x{cluster.start:08X}-0x{cluster.end:08X} "
                f"span=0x{cluster.span:X} overrun=0x{cluster.text_overrun:X} "
                f"matches={cluster.match_count}"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile dormant SDK imports and compare their emitted object spans against the active config."
    )
    parser.add_argument("sources", nargs="+", help="Source files under src/ to probe")
    parser.add_argument("-v", "--version", default="GSAE01", help="Target version (default: GSAE01)")
    parser.add_argument(
        "--build-ninja",
        default="build.ninja",
        help="Path to build.ninja used to recover Dolphin compile flags",
    )
    parser.add_argument(
        "--output-root",
        default="temp/sdk_import_probe",
        help="Directory used for temporary object output",
    )
    parser.add_argument(
        "--extra-include",
        action="append",
        type=Path,
        default=[],
        help="Additional include directory passed as '-i'. Can be repeated.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue after compile failures when probing multiple sources.",
    )
    parser.add_argument(
        "--rank",
        action="store_true",
        help="Print a ranked one-line summary for all probed sources.",
    )
    parser.add_argument(
        "--hypothesis-limit",
        type=int,
        default=3,
        help="Maximum start hypotheses to print per source (default: 3).",
    )
    parser.add_argument(
        "--cluster-limit",
        type=int,
        default=2,
        help="Maximum translated clusters to print per source (default: 2).",
    )
    parser.add_argument(
        "--cluster-min-score",
        type=int,
        default=6,
        help="Minimum translated candidate score used to seed source clusters (default: 6).",
    )
    parser.add_argument(
        "--cluster-gap",
        type=lambda value: int(value, 0),
        default=0x100,
        help="Maximum translated cluster gap in bytes (default: 0x100).",
    )
    parser.add_argument(
        "--require-cluster-provenance",
        action="store_true",
        help="Only use translated symbols with Dolphin library/object provenance when building source clusters.",
    )
    parser.add_argument(
        "--show-functions",
        action="store_true",
        help="Print projected per-function addresses for each start hypothesis.",
    )
    parser.add_argument(
        "--function-limit",
        type=int,
        default=0,
        help="Maximum projected functions to print per hypothesis (default: 0 = all).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    build_config = parse_build_config(Path(args.build_ninja), args.version)
    output_root = Path(args.output_root)
    config_symbols_path = Path("config") / args.version / "symbols.txt"
    extra_include_dirs = tuple(args.extra_include)
    reports: list[SourceReport] = []

    for source_arg in args.sources:
        source = Path(source_arg)
        if not source.is_file():
            if args.keep_going:
                print(f"# {source.as_posix()}")
                print(f"error: missing source file: {source}")
                print()
                continue
            raise SystemExit(f"Missing source file: {source}")

        object_dir = output_root / source.with_suffix("")
        try:
            translated_clusters = build_translated_clusters(
                version=args.version,
                source=source,
                min_score=args.cluster_min_score,
                require_provenance=args.require_cluster_provenance,
                gap=args.cluster_gap,
            )
            report = analyze_source(
                version=args.version,
                config_symbols_path=config_symbols_path,
                source=source,
                build_config=build_config,
                output_root=object_dir,
                extra_include_dirs=extra_include_dirs,
                translated_clusters=translated_clusters,
            )
        except subprocess.CalledProcessError as exc:
            if args.keep_going:
                print(f"# {source.as_posix()}")
                print(f"error: compile failed with exit code {exc.returncode}")
                print()
                continue
            raise
        reports.append(report)

    if args.rank:
        print_ranked_summary(args.version, reports)
        return

    for report in reports:
        print_report(
            args.version,
            report,
            args.hypothesis_limit,
            args.cluster_limit,
            args.show_functions,
            args.function_limit,
        )


if __name__ == "__main__":
    sys.exit(main())
