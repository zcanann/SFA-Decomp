from __future__ import annotations

import argparse
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from dolphin_sdk_symbols import load_config_symbols, load_splits


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
    text_size: int
    anchors: tuple[AnchorCandidate, ...]
    hypotheses: tuple[StartHypothesis, ...]


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
) -> SourceReport:
    object_path = compile_source(
        source,
        build_config,
        version,
        output_root,
        extra_include_dirs=extra_include_dirs,
    )
    sections, symbols = parse_llvm_readobj(object_path)
    anchors = find_anchor_candidates(symbols, config_symbols_path)
    text_size = next((section.size for section in sections if section.name == ".text"), 0)
    return SourceReport(
        source=source,
        sections=tuple(sections),
        text_size=text_size,
        anchors=tuple(anchors),
        hypotheses=tuple(build_start_hypotheses(anchors)),
    )


def print_report(
    version: str,
    report: SourceReport,
    hypothesis_limit: int,
) -> None:
    print(f"# {report.source.as_posix()}")
    print("sections:")
    for section in report.sections:
        if section.name.startswith(".rela") or section.name in {".symtab", ".strtab", ".shstrtab", ".comment"}:
            continue
        print(f"  {section.name:<8} 0x{section.size:X}")

    if not report.anchors:
        print("anchors: none")
        print()
        return

    print("start hypotheses:")
    for hypothesis in report.hypotheses[:hypothesis_limit]:
        span_end = hypothesis.start + report.text_size
        overlaps = describe_overlap(version, hypothesis.start, span_end)
        print(
            f"  0x{hypothesis.start:08X}-0x{span_end:08X} size=0x{report.text_size:X} "
            f"anchors={len(hypothesis.anchors)} exact-size={hypothesis.exact_count} "
            f"overlaps={len(overlaps)}"
        )
        if overlaps:
            for overlap in overlaps[:5]:
                print(f"    {overlap}")
            if len(overlaps) > 5:
                print(f"    ... {len(overlaps) - 5} more")

        print("  anchor details:")
        for anchor in hypothesis.anchors:
            symbol = anchor.compiled_symbol
            exact_text = "yes" if anchor.size_matches else "no"
            print(
                f"    +0x{symbol.value:04X} {symbol.name:<28} "
                f"size=0x{symbol.size:X} addr=0x{anchor.config_address:08X} size-match={exact_text}"
            )
    print()


def print_ranked_summary(version: str, reports: list[SourceReport]) -> None:
    ranked: list[tuple[int, int, int, int, SourceReport, StartHypothesis | None]] = []
    for report in reports:
        best = report.hypotheses[0] if report.hypotheses else None
        overlap_count = 9999
        if best is not None:
            overlap_count = len(describe_overlap(version, best.start, best.start + report.text_size))
        ranked.append(
            (
                len(best.anchors) if best is not None else 0,
                best.exact_count if best is not None else 0,
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
            -item[3],
            item[4].source.as_posix(),
        )
    )

    for anchor_count, exact_count, neg_overlap_count, _, report, best in ranked:
        if best is None:
            print(
                f"anchors=0 exact=0 overlaps=0 text=0x{report.text_size:X} "
                f"{report.source.as_posix()} -"
            )
            continue

        overlap_count = -neg_overlap_count
        span_end = best.start + report.text_size
        names = ", ".join(anchor.compiled_symbol.name for anchor in best.anchors[:5])
        print(
            f"anchors={anchor_count} exact={exact_count} overlaps={overlap_count} "
            f"text=0x{report.text_size:X} {report.source.as_posix()} "
            f"0x{best.start:08X}-0x{span_end:08X}"
        )
        if names:
            print(f"  names={names}")


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

        object_dir = output_root / source.stem
        try:
            report = analyze_source(
                version=args.version,
                config_symbols_path=config_symbols_path,
                source=source,
                build_config=build_config,
                output_root=object_dir,
                extra_include_dirs=extra_include_dirs,
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
        print_report(args.version, report, args.hypothesis_limit)


if __name__ == "__main__":
    sys.exit(main())
