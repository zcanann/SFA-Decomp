from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from difflib import SequenceMatcher
from functools import cached_property, lru_cache
from itertools import zip_longest
from pathlib import Path

from dolphin_sdk_symbols import ConfigSymbol, SplitRange, load_config_symbols, load_splits
from orig.dol_xrefs import DolFile
from sdk_import_probe import find_assigned_text_split, load_auto_text_functions


DEFAULT_REFERENCE_SPECS = (
    "animal_crossing:GAFE01",
    "pikmin2:GPVE01",
    "marioparty4:GMPE01",
    "twilight_princess:GZ2E01",
)
DEFAULT_SDK_FILTERS = (
    "MSL_C",
    "dolphin/",
    "Dolphin/",
    "Runtime.PPCEABI",
    "TRK_MINNOW",
)
TOP16_MASK_OPCODES = {
    7,
    8,
    10,
    11,
    12,
    13,
    14,
    15,
    24,
    25,
    26,
    27,
    28,
    29,
    32,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    43,
    44,
    45,
    46,
    47,
    48,
    49,
    50,
    51,
    52,
    53,
    54,
    55,
}
TOP16_LOW2_MASK_OPCODES = {56, 57, 60, 61}


@dataclass(frozen=True)
class ReferenceSpec:
    project: str
    config: str

    @property
    def root(self) -> Path:
        return Path("reference_projects") / self.project

    @property
    def label(self) -> str:
        return f"{self.project}:{self.config}"

    @property
    def splits_path(self) -> Path:
        return self.root / "config" / self.config / "splits.txt"

    @property
    def symbols_path(self) -> Path:
        return self.root / "config" / self.config / "symbols.txt"

    @property
    def dol_path(self) -> Path:
        return self.root / "orig" / self.config / "sys" / "main.dol"


@dataclass(frozen=True)
class FunctionSignature:
    start: int
    end: int
    size: int
    name: str
    words: tuple[int, ...]
    masked_words: tuple[int, ...]


@dataclass(frozen=True)
class WindowSignature:
    label: str
    source_path: str
    game: str
    start: int
    end: int
    functions: tuple[FunctionSignature, ...]

    @cached_property
    def span(self) -> int:
        return self.end - self.start

    @cached_property
    def function_count(self) -> int:
        return len(self.functions)

    @cached_property
    def size_vector(self) -> tuple[int, ...]:
        return tuple(function.size for function in self.functions)

    @cached_property
    def flat_masked_words(self) -> tuple[int, ...]:
        return tuple(word for function in self.functions for word in function.masked_words)


@dataclass(frozen=True)
class MatchResult:
    candidate: WindowSignature
    overall_score: float
    function_mask_score: float
    window_mask_score: float
    ngram_score: float
    size_score: float
    count_score: float
    exact_size_matches: int
    compared_function_count: int


def parse_reference_spec(value: str) -> ReferenceSpec:
    if ":" not in value:
        raise argparse.ArgumentTypeError(f"Reference spec must be project:config, got {value!r}")
    project, config = value.split(":", 1)
    project = project.strip()
    config = config.strip()
    root = Path("reference_projects") / project
    config_root = root / "config"
    if not config_root.is_dir():
        raise argparse.ArgumentTypeError(f"Missing reference project: {project}")

    config_dir = config_root / config
    if not config_dir.is_dir():
        matches = sorted(path.name for path in config_root.iterdir() if path.is_dir() and path.name.startswith(config))
        if len(matches) == 1:
            config = matches[0]
        elif len(matches) > 1:
            revision_zero = [match for match in matches if match.endswith("_00")]
            if len(revision_zero) == 1:
                config = revision_zero[0]
            else:
                joined = ", ".join(matches)
                raise argparse.ArgumentTypeError(
                    f"Reference config {project}:{config} is ambiguous; matches: {joined}"
                )

    spec = ReferenceSpec(project=project, config=config)
    if not spec.splits_path.is_file():
        raise argparse.ArgumentTypeError(f"Missing splits file for {spec.label}: {spec.splits_path}")
    if not spec.symbols_path.is_file():
        raise argparse.ArgumentTypeError(f"Missing symbols file for {spec.label}: {spec.symbols_path}")
    if not spec.dol_path.is_file():
        raise argparse.ArgumentTypeError(f"Missing DOL for {spec.label}: {spec.dol_path}")
    return spec


def parse_int(value: str) -> int:
    return int(value, 0)


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").strip()


def matches_path_filters(path: str, filters: tuple[str, ...]) -> bool:
    if not filters:
        return True
    path_lower = path.lower()
    return any(filter_value.lower() in path_lower for filter_value in filters)


def read_dol_range(dol: DolFile, start: int, end: int) -> bytes:
    if end < start:
        raise ValueError(f"Invalid range 0x{start:X}-0x{end:X}")

    chunks = bytearray()
    cursor = start
    while cursor < end:
        section = next(
            (
                section
                for section in dol.text_sections
                if section.address <= cursor < section.address + section.size
            ),
            None,
        )
        if section is None:
            raise ValueError(
                f"Address 0x{cursor:08X} is not covered by a DOL text section in {dol.path}"
            )
        chunk_end = min(end, section.address + section.size)
        offset = section.offset + (cursor - section.address)
        chunks.extend(dol.data[offset : offset + (chunk_end - cursor)])
        cursor = chunk_end
    return bytes(chunks)


def mask_instruction(word: int) -> int:
    opcode = word >> 26
    if opcode == 18:
        return word & 0xFC000003
    if opcode == 16:
        return word & 0xFFFF0003
    if opcode in TOP16_MASK_OPCODES:
        return word & 0xFFFF0000
    if opcode in TOP16_LOW2_MASK_OPCODES:
        return word & 0xFFFF0003
    return word


def build_function_signature(dol: DolFile, start: int, end: int, name: str) -> FunctionSignature:
    raw = read_dol_range(dol, start, end)
    words = tuple(struct.unpack_from(">I", raw, offset)[0] for offset in range(0, len(raw), 4))
    return FunctionSignature(
        start=start,
        end=end,
        size=end - start,
        name=name,
        words=words,
        masked_words=tuple(mask_instruction(word) for word in words),
    )


def build_window_signature(
    dol: DolFile,
    label: str,
    source_path: str,
    game: str,
    functions: tuple[tuple[int, int, str], ...],
) -> WindowSignature:
    signature_functions = tuple(
        build_function_signature(dol, start, end, name)
        for start, end, name in functions
    )
    return WindowSignature(
        label=label,
        source_path=source_path,
        game=game,
        start=signature_functions[0].start,
        end=signature_functions[-1].end,
        functions=signature_functions,
    )


def sequence_ratio(left: tuple[int, ...], right: tuple[int, ...]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    return SequenceMatcher(None, left, right, autojunk=False).ratio()


def build_ngrams(words: tuple[int, ...], size: int) -> set[tuple[int, ...]]:
    if not words:
        return set()
    if len(words) <= size:
        return {words}
    return {tuple(words[index : index + size]) for index in range(len(words) - size + 1)}


def jaccard_score(left: tuple[int, ...], right: tuple[int, ...]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    ngram_size = 4 if min(len(left), len(right)) >= 4 else 2
    left_ngrams = build_ngrams(left, ngram_size)
    right_ngrams = build_ngrams(right, ngram_size)
    if not left_ngrams and not right_ngrams:
        return 1.0
    union = left_ngrams | right_ngrams
    if not union:
        return 0.0
    return len(left_ngrams & right_ngrams) / len(union)


def compare_windows(target: WindowSignature, candidate: WindowSignature) -> MatchResult:
    target_count = target.function_count
    candidate_count = candidate.function_count
    compared_pairs = [
        (left, right)
        for left, right in zip_longest(target.functions, candidate.functions)
        if left is not None and right is not None
    ]
    compared_count = len(compared_pairs)

    exact_size_matches = sum(left.size == right.size for left, right in compared_pairs)
    function_mask_score = (
        sum(sequence_ratio(left.masked_words, right.masked_words) for left, right in compared_pairs)
        / compared_count
        if compared_count
        else 0.0
    )
    size_score = (
        sum(1.0 - (abs(left.size - right.size) / max(left.size, right.size)) for left, right in compared_pairs)
        / compared_count
        if compared_count
        else 0.0
    )
    count_score = 1.0 - (abs(target_count - candidate_count) / max(target_count, candidate_count))
    window_mask_score = sequence_ratio(target.flat_masked_words, candidate.flat_masked_words)
    ngram_score = jaccard_score(target.flat_masked_words, candidate.flat_masked_words)
    overall_score = (
        function_mask_score * 0.35
        + window_mask_score * 0.25
        + size_score * 0.20
        + ngram_score * 0.10
        + count_score * 0.10
    )
    return MatchResult(
        candidate=candidate,
        overall_score=overall_score,
        function_mask_score=function_mask_score,
        window_mask_score=window_mask_score,
        ngram_score=ngram_score,
        size_score=size_score,
        count_score=count_score,
        exact_size_matches=exact_size_matches,
        compared_function_count=compared_count,
    )


@lru_cache(maxsize=None)
def load_dol(path: Path) -> DolFile:
    return DolFile(path)


@lru_cache(maxsize=None)
def load_reference_symbols(path: Path) -> tuple[ConfigSymbol, ...]:
    return tuple(
        sorted(
            (
                symbol
                for symbol in load_config_symbols(path)
                if symbol.section == ".text" and symbol.size not in (None, 0)
            ),
            key=lambda symbol: symbol.address,
        )
    )


@lru_cache(maxsize=None)
def load_reference_text_splits(path: Path) -> tuple[SplitRange, ...]:
    return tuple(split for split in load_splits(path) if split.section == ".text")


def collect_reference_window_metadata(
    spec: ReferenceSpec,
    path_filters: tuple[str, ...],
) -> list[tuple[str, tuple[tuple[int, int, str], ...]]]:
    symbols = load_reference_symbols(spec.symbols_path)
    windows: list[tuple[str, tuple[tuple[int, int, str], ...]]] = []
    for split in load_reference_text_splits(spec.splits_path):
        split_path = normalize_path(split.path)
        if not matches_path_filters(split_path, path_filters):
            continue
        functions = tuple(
            (symbol.address, symbol.address + symbol.size, symbol.name)
            for symbol in symbols
            if split.start <= symbol.address and symbol.address + symbol.size <= split.end
        )
        if not functions:
            continue
        windows.append((split_path, functions))
    return windows


def collect_reference_windows(
    spec: ReferenceSpec,
    path_filters: tuple[str, ...],
) -> list[WindowSignature]:
    dol = load_dol(spec.dol_path)
    windows: list[WindowSignature] = []
    for split_path, functions in collect_reference_window_metadata(spec, path_filters):
        windows.append(
            build_window_signature(
                dol=dol,
                label=spec.label,
                source_path=split_path,
                game=spec.label,
                functions=functions,
            )
        )
    return windows


def select_reference_window(spec: ReferenceSpec, source_query: str) -> WindowSignature:
    normalized_query = normalize_path(source_query).lower()
    candidates = []
    for window in collect_reference_windows(spec, ()):
        source_lower = window.source_path.lower()
        if source_lower == normalized_query or source_lower.endswith(normalized_query):
            candidates.append(window)
    if not candidates:
        raise SystemExit(f"No reference split matching {source_query!r} found in {spec.label}")
    if len(candidates) > 1:
        matches = "\n".join(f"  {candidate.source_path}" for candidate in candidates[:12])
        raise SystemExit(
            f"Reference source {source_query!r} is ambiguous in {spec.label}:\n{matches}"
        )
    return candidates[0]


def target_dol_path_for_version(version: str) -> Path:
    path = Path("orig") / version / "sys" / "main.dol"
    if not path.is_file():
        raise SystemExit(f"Missing target DOL: {path}")
    return path


@lru_cache(maxsize=None)
def load_target_functions(version: str, dol_path: Path) -> tuple[FunctionSignature, ...]:
    dol = load_dol(dol_path)
    return tuple(
        build_function_signature(dol, function.start, function.end, function.name)
        for function in load_auto_text_functions(version)
    )


def build_target_window_from_range(
    version: str,
    dol_path: Path,
    start: int,
    end: int,
) -> WindowSignature:
    functions = tuple(
        function
        for function in load_target_functions(version, dol_path)
        if start <= function.start and function.end <= end
    )
    if not functions:
        raise SystemExit(f"No auto asm functions fully contained in 0x{start:08X}-0x{end:08X}")
    return WindowSignature(
        label=version,
        source_path=f"range:0x{start:08X}-0x{end:08X}",
        game=version,
        start=functions[0].start,
        end=functions[-1].end,
        functions=functions,
    )


def build_target_window_from_source(
    version: str,
    dol_path: Path,
    source_path: Path,
) -> WindowSignature:
    split = find_assigned_text_split(version, source_path)
    if split is None:
        raise SystemExit(f"No assigned .text split found for {source_path.as_posix()} in {version}")
    return build_target_window_from_range(version, dol_path, split.start, split.end)


def iter_target_windows(
    version: str,
    dol_path: Path,
    function_count: int,
    range_start: int | None,
    range_end: int | None,
) -> tuple[WindowSignature, ...]:
    functions = load_target_functions(version, dol_path)
    if function_count <= 0 or function_count > len(functions):
        return ()

    windows: list[WindowSignature] = []
    for index in range(len(functions) - function_count + 1):
        chunk = functions[index : index + function_count]
        window_start = chunk[0].start
        window_end = chunk[-1].end
        if range_start is not None and window_end <= range_start:
            continue
        if range_end is not None and window_start >= range_end:
            break
        windows.append(
            WindowSignature(
                label=version,
                source_path=f"range:0x{window_start:08X}-0x{window_end:08X}",
                game=version,
                start=window_start,
                end=window_end,
                functions=chunk,
            )
        )
    return tuple(windows)


def rank_candidates(target: WindowSignature, candidates: list[WindowSignature], limit: int) -> list[MatchResult]:
    results = [compare_windows(target, candidate) for candidate in candidates]
    results.sort(
        key=lambda result: (
            -result.overall_score,
            -result.exact_size_matches,
            abs(result.candidate.span - target.span),
            result.candidate.game,
            result.candidate.start,
        )
    )
    return results[:limit]


def verdict_for_result(result: MatchResult) -> str:
    if (
        result.overall_score >= 0.88
        and result.size_score >= 0.96
        and result.count_score >= 0.999
    ):
        return "source-likely"
    if result.overall_score >= 0.74 and result.size_score >= 0.85:
        return "structural"
    return "weak"


def print_window(label: str, window: WindowSignature) -> None:
    print(
        f"{label}: {window.source_path} 0x{window.start:08X}-0x{window.end:08X} "
        f"span=0x{window.span:X} funcs={window.function_count}"
    )
    print(f"  sizes={','.join(f'0x{size:X}' for size in window.size_vector)}")


def print_match_results(target: WindowSignature, results: list[MatchResult]) -> None:
    print_window("target", target)
    print("matches:")
    for index, result in enumerate(results, start=1):
        candidate = result.candidate
        print(
            f"  {index:>2}. {candidate.game} {candidate.source_path} "
            f"0x{candidate.start:08X}-0x{candidate.end:08X} span=0x{candidate.span:X} "
            f"funcs={candidate.function_count} score={result.overall_score * 100:.2f} "
            f"{verdict_for_result(result)}"
        )
        print(
            f"      mask-fn={result.function_mask_score * 100:.2f} "
            f"mask-win={result.window_mask_score * 100:.2f} "
            f"ngram={result.ngram_score * 100:.2f} "
            f"size={result.size_score * 100:.2f} "
            f"count={result.count_score * 100:.2f} "
            f"exact-sizes={result.exact_size_matches}/{result.compared_function_count}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare normalized PPC DOL signatures across reference-game SDK splits "
            "and SFA text windows."
        )
    )
    parser.add_argument("-v", "--version", default="GSAE01", help="Target SFA version")
    parser.add_argument(
        "--reference",
        type=parse_reference_spec,
        action="append",
        default=[],
        help="Reference project and config, in project:config form",
    )
    parser.add_argument("--source", type=Path, help="Target SFA source path with an assigned split")
    parser.add_argument("--range-start", type=parse_int, help="Target SFA range start")
    parser.add_argument("--range-end", type=parse_int, help="Target SFA range end")
    parser.add_argument(
        "--reference-source",
        help="Reference split path to search for inside the SFA DOL",
    )
    parser.add_argument(
        "--path-contains",
        action="append",
        default=[],
        help="Substring filter applied to reference split paths",
    )
    parser.add_argument(
        "--all-splits",
        action="store_true",
        help="Disable the default SDK-oriented path filters",
    )
    parser.add_argument(
        "--target-range-start",
        type=parse_int,
        help="Optional SFA search window start for --reference-source mode",
    )
    parser.add_argument(
        "--target-range-end",
        type=parse_int,
        help="Optional SFA search window end for --reference-source mode",
    )
    parser.add_argument("--limit", type=int, default=20, help="Number of matches to show")
    args = parser.parse_args()

    if not args.reference:
        args.reference = [parse_reference_spec(value) for value in DEFAULT_REFERENCE_SPECS]

    source_mode = args.source is not None or args.range_start is not None or args.range_end is not None
    reference_mode = args.reference_source is not None
    if source_mode == reference_mode:
        parser.error(
            "Choose exactly one mode: either --source/--range-start+--range-end, "
            "or --reference-source"
        )
    if (args.range_start is None) != (args.range_end is None):
        parser.error("--range-start and --range-end must be provided together")
    if args.range_start is not None and args.range_end <= args.range_start:
        parser.error("--range-end must be greater than --range-start")
    if args.reference_source is not None and len(args.reference) != 1:
        parser.error("--reference-source mode requires exactly one --reference")
    if args.target_range_start is not None and args.target_range_end is not None:
        if args.target_range_end <= args.target_range_start:
            parser.error("--target-range-end must be greater than --target-range-start")
    if (args.target_range_start is None) != (args.target_range_end is None):
        parser.error("--target-range-start and --target-range-end must be provided together")
    return args


def main() -> None:
    args = parse_args()
    dol_path = target_dol_path_for_version(args.version)

    if args.reference_source is not None:
        spec = args.reference[0]
        reference_window = select_reference_window(spec, args.reference_source)
        candidates = list(
            iter_target_windows(
                version=args.version,
                dol_path=dol_path,
                function_count=reference_window.function_count,
                range_start=args.target_range_start,
                range_end=args.target_range_end,
            )
        )
        if not candidates:
            raise SystemExit("No SFA target windows available for the requested search")
        results = rank_candidates(reference_window, candidates, args.limit)
        print_window("reference", reference_window)
        print("matches:")
        for index, result in enumerate(results, start=1):
            candidate = result.candidate
            print(
                f"  {index:>2}. {candidate.source_path} "
                f"0x{candidate.start:08X}-0x{candidate.end:08X} span=0x{candidate.span:X} "
                f"score={result.overall_score * 100:.2f} "
                f"mask-fn={result.function_mask_score * 100:.2f} "
                f"mask-win={result.window_mask_score * 100:.2f} "
                f"size={result.size_score * 100:.2f} "
                f"exact-sizes={result.exact_size_matches}/{result.compared_function_count} "
                f"{verdict_for_result(result)}"
            )
        return

    if args.source is not None:
        target_window = build_target_window_from_source(args.version, dol_path, args.source)
    else:
        target_window = build_target_window_from_range(
            args.version,
            dol_path,
            args.range_start,
            args.range_end,
        )

    if args.all_splits:
        path_filters = tuple(args.path_contains)
    else:
        path_filters = tuple(args.path_contains) or DEFAULT_SDK_FILTERS

    candidates: list[WindowSignature] = []
    for spec in args.reference:
        candidates.extend(collect_reference_windows(spec, path_filters))
    if not candidates:
        raise SystemExit("No reference windows matched the requested filters")

    results = rank_candidates(target_window, candidates, args.limit)
    print_match_results(target_window, results)


if __name__ == "__main__":
    main()
