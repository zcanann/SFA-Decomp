from __future__ import annotations

import argparse
import heapq
import struct
from dataclasses import dataclass
from difflib import SequenceMatcher
from functools import cached_property, lru_cache
from itertools import zip_longest
from pathlib import Path
import re

from dolphin_sdk_symbols import ConfigSymbol, SplitRange, load_config_symbols, load_splits
from orig.dol_xrefs import DolFile
from sdk_import_probe import AsmTextFunction, find_assigned_text_split, load_text_functions


DEFAULT_REFERENCE_SPECS = (
    "animal_crossing:GAFE01",
    "pikmin2:GPVE01",
    "marioparty4:GMPE01",
    "super_mario_sunshine:GMSJ01",
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
    def config_yml_path(self) -> Path:
        return self.root / "config" / self.config / "config.yml"

    @property
    def dol_path(self) -> Path:
        object_path = configured_reference_object_path(self.config_yml_path)
        if object_path is not None:
            return self.root / object_path
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

    @cached_property
    def first_size(self) -> int:
        return self.functions[0].size

    @cached_property
    def last_size(self) -> int:
        return self.functions[-1].size

    @cached_property
    def max_function_size(self) -> int:
        return max(function.size for function in self.functions)


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


@dataclass(frozen=True)
class DiscoveryHit:
    reference: WindowSignature
    target: WindowSignature
    overall_score: float
    function_mask_score: float
    window_mask_score: float
    ngram_score: float
    size_score: float
    count_score: float
    exact_size_matches: int
    compared_function_count: int


@dataclass(frozen=True)
class ReferenceSourceHit:
    reference: WindowSignature
    result: MatchResult


@dataclass(frozen=True)
class ReferenceSourceAggregate:
    target: WindowSignature
    hits: tuple[ReferenceSourceHit, ...]
    average_score: float
    best_score: float


@dataclass(frozen=True)
class RawWindow:
    source_path: str
    game: str
    start: int
    end: int
    function_defs: tuple[tuple[int, int, str], ...]

    @cached_property
    def span(self) -> int:
        return self.end - self.start

    @cached_property
    def function_count(self) -> int:
        return len(self.function_defs)

    @cached_property
    def size_vector(self) -> tuple[int, ...]:
        return tuple(end - start for start, end, _ in self.function_defs)

    @cached_property
    def first_size(self) -> int:
        return self.size_vector[0]

    @cached_property
    def last_size(self) -> int:
        return self.size_vector[-1]

    @cached_property
    def max_function_size(self) -> int:
        return max(self.size_vector)


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
        raise argparse.ArgumentTypeError(
            f"Missing DOL for {spec.label}: {spec.dol_path} "
            f"(splits/symbols exist, so this ref is inventory-ready but not matcher-ready yet)"
        )
    return spec


def parse_int(value: str) -> int:
    return int(value, 0)


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").strip()


def configured_reference_object_path(config_yml_path: Path) -> Path | None:
    if not config_yml_path.is_file():
        return None
    text = config_yml_path.read_text(encoding="utf-8", errors="replace")
    object_base_match = re.search(r"^object_base:\s*(.+?)\s*$", text, re.MULTILINE)
    object_match = re.search(r"^object:\s*(.+?)\s*$", text, re.MULTILINE)
    if object_base_match is None or object_match is None:
        return None
    object_base = object_base_match.group(1).strip()
    object_rel = object_match.group(1).strip()
    return Path(object_base) / object_rel


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


@lru_cache(maxsize=None)
def build_target_function_signature(
    version: str,
    dol_path: Path,
    start: int,
    end: int,
    name: str,
) -> FunctionSignature:
    return build_function_signature(load_dol(dol_path), start, end, name)


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


def build_window_signature_from_defs(
    dol: DolFile,
    label: str,
    source_path: str,
    game: str,
    function_defs: tuple[tuple[int, int, str], ...],
) -> WindowSignature:
    return build_window_signature(
        dol=dol,
        label=label,
        source_path=source_path,
        game=game,
        functions=function_defs,
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


@lru_cache(maxsize=None)
def load_target_text_splits(version: str) -> tuple[SplitRange, ...]:
    return tuple(
        split
        for split in load_splits(Path("config") / version / "splits.txt")
        if split.section == ".text"
    )


def describe_target_split_overlap(version: str, start: int, end: int) -> str:
    overlaps = [
        split
        for split in load_target_text_splits(version)
        if split.start < end and start < split.end
    ]
    if not overlaps:
        return "ownership=unassigned"

    if len(overlaps) == 1:
        split = overlaps[0]
        span_label = f"{split.path}@0x{split.start:08X}-0x{split.end:08X}"
        if split.start == start and split.end == end:
            return f"ownership=split-exact {span_label}"
        if split.start <= start and end <= split.end:
            return f"ownership=inside {span_label}"
        return f"ownership=partial {span_label}"

    preview = ", ".join(
        f"{split.path}@0x{split.start:08X}-0x{split.end:08X}"
        for split in overlaps[:3]
    )
    if len(overlaps) > 3:
        preview += f", ... ({len(overlaps)} total)"
    return f"ownership=crosses {preview}"


@lru_cache(maxsize=None)
def load_target_ownership_prefix(version: str) -> tuple[int, ...]:
    splits = load_target_text_splits(version)
    functions = load_text_functions(version)
    owned_prefix = [0]
    split_index = 0
    for function in functions:
        while split_index < len(splits) and splits[split_index].end <= function.start:
            split_index += 1
        owned = (
            split_index < len(splits)
            and splits[split_index].start <= function.start
            and function.end <= splits[split_index].end
        )
        owned_prefix.append(owned_prefix[-1] + (1 if owned else 0))
    return tuple(owned_prefix)


def collect_reference_window_metadata(
    spec: ReferenceSpec,
    path_filters: tuple[str, ...],
    min_functions: int = 1,
    min_span: int = 0,
    min_largest_function: int = 0,
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
        span = functions[-1][1] - functions[0][0]
        max_function_size = max(end - start for start, end, _ in functions)
        if (
            len(functions) < min_functions
            or span < min_span
            or max_function_size < min_largest_function
        ):
            continue
        windows.append((split_path, functions))
    return windows


def collect_reference_raw_windows(
    spec: ReferenceSpec,
    path_filters: tuple[str, ...],
    min_functions: int = 1,
    min_span: int = 0,
    min_largest_function: int = 0,
) -> list[RawWindow]:
    return [
        RawWindow(
            source_path=split_path,
            game=spec.label,
            start=functions[0][0],
            end=functions[-1][1],
            function_defs=functions,
        )
        for split_path, functions in collect_reference_window_metadata(
            spec,
                path_filters,
                min_functions=min_functions,
                min_span=min_span,
                min_largest_function=min_largest_function,
            )
    ]


def collect_reference_windows(
    spec: ReferenceSpec,
    path_filters: tuple[str, ...],
    min_functions: int = 1,
    min_span: int = 0,
    min_largest_function: int = 0,
) -> list[WindowSignature]:
    dol = load_dol(spec.dol_path)
    windows: list[WindowSignature] = []
    for split_path, functions in collect_reference_window_metadata(
        spec,
            path_filters,
            min_functions=min_functions,
            min_span=min_span,
            min_largest_function=min_largest_function,
        ):
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


def build_target_window_signature(
    version: str,
    dol_path: Path,
    raw_window: RawWindow,
) -> WindowSignature:
    return WindowSignature(
        label=version,
        source_path=raw_window.source_path,
        game=version,
        start=raw_window.start,
        end=raw_window.end,
        functions=tuple(
            build_target_function_signature(version, dol_path, start, end, name)
            for start, end, name in raw_window.function_defs
        ),
    )


def build_target_window_from_range(
    version: str,
    dol_path: Path,
    start: int,
    end: int,
) -> WindowSignature:
    functions = tuple(
        build_target_function_signature(version, dol_path, function.start, function.end, function.name)
        for function in load_text_functions(version)
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


def window_is_unassigned(version: str, start: int, end: int) -> bool:
    return all(split.end <= start or split.start >= end for split in load_target_text_splits(version))


def iter_target_windows(
    version: str,
    dol_path: Path,
    function_count: int,
    range_start: int | None,
    range_end: int | None,
    only_unassigned: bool = False,
) -> tuple[WindowSignature, ...]:
    functions = load_text_functions(version)
    if function_count <= 0 or function_count > len(functions):
        return ()

    ownership_prefix = load_target_ownership_prefix(version) if only_unassigned else ()
    windows: list[WindowSignature] = []
    for index in range(len(functions) - function_count + 1):
        chunk = functions[index : index + function_count]
        window_start = chunk[0].start
        window_end = chunk[-1].end
        if range_start is not None and window_end <= range_start:
            continue
        if range_end is not None and window_start >= range_end:
            break
        if only_unassigned and ownership_prefix[index + function_count] != ownership_prefix[index]:
            continue
        windows.append(
            WindowSignature(
                label=version,
                source_path=f"range:0x{window_start:08X}-0x{window_end:08X}",
                game=version,
                start=window_start,
                end=window_end,
                functions=tuple(
                    build_target_function_signature(version, dol_path, function.start, function.end, function.name)
                    for function in chunk
                ),
            )
        )
    return tuple(windows)


def coarse_size_score(target: WindowSignature, candidate: WindowSignature) -> float:
    compared_pairs = list(zip(target.size_vector, candidate.size_vector))
    if not compared_pairs:
        return 0.0
    vector_score = sum(
        1.0 - (abs(left - right) / max(left, right))
        for left, right in compared_pairs
    ) / len(compared_pairs)
    span_score = 1.0 - (abs(target.span - candidate.span) / max(target.span, candidate.span))
    edge_score = (
        1.0 - (abs(target.first_size - candidate.first_size) / max(target.first_size, candidate.first_size))
        + 1.0 - (abs(target.last_size - candidate.last_size) / max(target.last_size, candidate.last_size))
    ) / 2.0
    return vector_score * 0.6 + span_score * 0.25 + edge_score * 0.15


def coarse_size_score_raw(target: RawWindow, candidate: RawWindow) -> float:
    compared_pairs = list(zip(target.size_vector, candidate.size_vector))
    if not compared_pairs:
        return 0.0
    vector_score = sum(
        1.0 - (abs(left - right) / max(left, right))
        for left, right in compared_pairs
    ) / len(compared_pairs)
    span_score = 1.0 - (abs(target.span - candidate.span) / max(target.span, candidate.span))
    edge_score = (
        1.0 - (abs(target.first_size - candidate.first_size) / max(target.first_size, candidate.first_size))
        + 1.0 - (abs(target.last_size - candidate.last_size) / max(target.last_size, candidate.last_size))
    ) / 2.0
    return vector_score * 0.6 + span_score * 0.25 + edge_score * 0.15


def prefilter_candidates(
    target: WindowSignature,
    candidates: list[WindowSignature],
    coarse_limit: int | None,
) -> list[WindowSignature]:
    if coarse_limit is None or coarse_limit <= 0 or len(candidates) <= coarse_limit:
        return candidates
    scored = heapq.nlargest(
        coarse_limit,
        ((coarse_size_score(target, candidate), candidate) for candidate in candidates),
        key=lambda item: (item[0], -abs(item[1].span - target.span), -item[1].function_count),
    )
    return [candidate for _, candidate in scored]


def prefilter_raw_candidates(
    target: RawWindow,
    candidates: tuple[RawWindow, ...],
    coarse_limit: int | None,
) -> list[RawWindow]:
    if coarse_limit is None or coarse_limit <= 0 or len(candidates) <= coarse_limit:
        return list(candidates)
    scored = heapq.nlargest(
        coarse_limit,
        ((coarse_size_score_raw(target, candidate), candidate) for candidate in candidates),
        key=lambda item: (item[0], -abs(item[1].span - target.span), -item[1].function_count),
    )
    return [candidate for _, candidate in scored]


def rank_candidates(
    target: WindowSignature,
    candidates: list[WindowSignature],
    limit: int,
    coarse_limit: int | None = None,
) -> list[MatchResult]:
    shortlisted = prefilter_candidates(target, candidates, coarse_limit)
    results = [compare_windows(target, candidate) for candidate in shortlisted]
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


def discover_reference_hits(
    version: str,
    dol_path: Path,
    references: list[RawWindow],
    range_start: int,
    range_end: int,
    min_score: float,
    limit: int,
    limit_per_reference: int,
    only_unassigned: bool,
    coarse_limit: int | None,
    min_functions: int,
    min_span: int,
    min_largest_function: int,
) -> list[DiscoveryHit]:
    target_cache: dict[int, tuple[RawWindow, ...]] = {}
    best_by_target: dict[tuple[int, int], DiscoveryHit] = {}
    auto_functions = load_text_functions(version)
    ownership_prefix = load_target_ownership_prefix(version) if only_unassigned else ()
    reference_dol_cache: dict[str, DolFile] = {}

    for reference in references:
        if (
            reference.function_count < min_functions
            or reference.span < min_span
            or reference.max_function_size < min_largest_function
        ):
            continue
        target_windows = target_cache.get(reference.function_count)
        if target_windows is None:
            count = reference.function_count
            raw_windows: list[RawWindow] = []
            for index in range(len(auto_functions) - count + 1):
                chunk = auto_functions[index : index + count]
                window_start = chunk[0].start
                window_end = chunk[-1].end
                if range_start is not None and window_end <= range_start:
                    continue
                if range_end is not None and window_start >= range_end:
                    break
                if only_unassigned and ownership_prefix[index + count] != ownership_prefix[index]:
                    continue
                raw_window = RawWindow(
                    source_path=f"range:0x{window_start:08X}-0x{window_end:08X}",
                    game=version,
                    start=window_start,
                    end=window_end,
                    function_defs=tuple((function.start, function.end, function.name) for function in chunk),
                )
                if raw_window.max_function_size < min_largest_function:
                    continue
                raw_windows.append(raw_window)
            target_windows = tuple(raw_windows)
            target_cache[reference.function_count] = target_windows
        if not target_windows:
            continue

        shortlisted_targets = prefilter_raw_candidates(reference, target_windows, coarse_limit)
        if not shortlisted_targets:
            continue

        reference_dol = reference_dol_cache.get(reference.game)
        if reference_dol is None:
            project, config = reference.game.split(":", 1)
            reference_dol = load_dol(ReferenceSpec(project=project, config=config).dol_path)
            reference_dol_cache[reference.game] = reference_dol
        reference_signature = build_window_signature_from_defs(
            dol=reference_dol,
            label=reference.game,
            source_path=reference.source_path,
            game=reference.game,
            function_defs=reference.function_defs,
        )

        ranked = rank_candidates(
            reference_signature,
            [build_target_window_signature(version, dol_path, candidate) for candidate in shortlisted_targets],
            limit_per_reference,
            coarse_limit=None,
        )
        for result in ranked:
            if result.overall_score < min_score:
                continue
            key = (result.candidate.start, result.candidate.end)
            hit = DiscoveryHit(
                reference=reference_signature,
                target=result.candidate,
                overall_score=result.overall_score,
                function_mask_score=result.function_mask_score,
                window_mask_score=result.window_mask_score,
                ngram_score=result.ngram_score,
                size_score=result.size_score,
                count_score=result.count_score,
                exact_size_matches=result.exact_size_matches,
                compared_function_count=result.compared_function_count,
            )
            existing = best_by_target.get(key)
            if existing is None or hit.overall_score > existing.overall_score:
                best_by_target[key] = hit

    hits = sorted(
        best_by_target.values(),
        key=lambda hit: (
            -hit.overall_score,
            -hit.exact_size_matches,
            abs(hit.target.span - hit.reference.span),
            hit.target.start,
            hit.reference.game,
        ),
    )
    return hits[:limit]


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


def verdict_for_hit(hit: DiscoveryHit) -> str:
    if (
        hit.overall_score >= 0.88
        and hit.size_score >= 0.96
        and hit.count_score >= 0.999
    ):
        return "source-likely"
    if hit.overall_score >= 0.74 and hit.size_score >= 0.85:
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


def print_discovery_hits(
    version: str,
    range_start: int,
    range_end: int,
    only_unassigned: bool,
    min_score: float,
    hits: list[DiscoveryHit],
) -> None:
    assignment_mode = "unassigned-only" if only_unassigned else "all-windows"
    print(
        f"discovery: 0x{range_start:08X}-0x{range_end:08X} "
        f"mode={assignment_mode} min-score={min_score * 100:.2f}"
    )
    if not hits:
        print("matches:")
        print("   none")
        return
    print("matches:")
    for index, hit in enumerate(hits, start=1):
        print(
            f"  {index:>2}. 0x{hit.target.start:08X}-0x{hit.target.end:08X} "
            f"span=0x{hit.target.span:X} funcs={hit.target.function_count} "
            f"score={hit.overall_score * 100:.2f} {verdict_for_hit(hit)}"
        )
        print(f"      {describe_target_split_overlap(version, hit.target.start, hit.target.end)}")
        print(
            f"      ref={hit.reference.game} {hit.reference.source_path} "
            f"0x{hit.reference.start:08X}-0x{hit.reference.end:08X}"
        )
        print(
            f"      mask-fn={hit.function_mask_score * 100:.2f} "
            f"mask-win={hit.window_mask_score * 100:.2f} "
            f"ngram={hit.ngram_score * 100:.2f} "
            f"size={hit.size_score * 100:.2f} "
            f"count={hit.count_score * 100:.2f} "
            f"exact-sizes={hit.exact_size_matches}/{hit.compared_function_count}"
        )


def aggregate_reference_source_matches(
    version: str,
    dol_path: Path,
    specs: list[ReferenceSpec],
    source_query: str,
    target_range_start: int | None,
    target_range_end: int | None,
    only_unassigned: bool,
    coarse_limit: int | None,
    limit_per_reference: int,
    limit: int,
) -> tuple[list[ReferenceSourceAggregate], list[str]]:
    grouped_hits: dict[tuple[int, int], list[ReferenceSourceHit]] = {}
    missing_specs: list[str] = []

    for spec in specs:
        try:
            reference_window = select_reference_window(spec, source_query)
        except SystemExit:
            missing_specs.append(spec.label)
            continue

        candidates = list(
            iter_target_windows(
                version=version,
                dol_path=dol_path,
                function_count=reference_window.function_count,
                range_start=target_range_start,
                range_end=target_range_end,
                only_unassigned=only_unassigned,
            )
        )
        if not candidates:
            continue

        for result in rank_candidates(reference_window, candidates, limit_per_reference, coarse_limit):
            key = (result.candidate.start, result.candidate.end)
            grouped_hits.setdefault(key, []).append(
                ReferenceSourceHit(reference=reference_window, result=result)
            )

    aggregates: list[ReferenceSourceAggregate] = []
    for hits in grouped_hits.values():
        sorted_hits = tuple(
            sorted(
                hits,
                key=lambda hit: (
                    -hit.result.overall_score,
                    hit.reference.game,
                    hit.reference.start,
                ),
            )
        )
        target = sorted_hits[0].result.candidate
        average_score = sum(hit.result.overall_score for hit in sorted_hits) / len(sorted_hits)
        best_score = max(hit.result.overall_score for hit in sorted_hits)
        aggregates.append(
            ReferenceSourceAggregate(
                target=target,
                hits=sorted_hits,
                average_score=average_score,
                best_score=best_score,
            )
        )

    aggregates.sort(
        key=lambda aggregate: (
            -len(aggregate.hits),
            -aggregate.average_score,
            -aggregate.best_score,
            aggregate.target.start,
        )
    )
    return aggregates[:limit], missing_specs


def print_aggregated_reference_source_matches(
    version: str,
    source_query: str,
    range_start: int | None,
    range_end: int | None,
    only_unassigned: bool,
    specs: list[ReferenceSpec],
    aggregates: list[ReferenceSourceAggregate],
    missing_specs: list[str],
) -> None:
    assignment_mode = "unassigned-only" if only_unassigned else "all-windows"
    range_label = "full-range"
    if range_start is not None and range_end is not None:
        range_label = f"0x{range_start:08X}-0x{range_end:08X}"
    print(
        f"reference-source aggregate: {source_query!r} "
        f"range={range_label} mode={assignment_mode} refs={len(specs)}"
    )
    if missing_specs:
        print("missing-reference-source:")
        for label in missing_specs:
            print(f"  {label}")
    if not aggregates:
        print("matches:")
        print("   none")
        return
    print("matches:")
    for index, aggregate in enumerate(aggregates, start=1):
        target = aggregate.target
        print(
            f"  {index:>2}. {target.source_path} "
            f"0x{target.start:08X}-0x{target.end:08X} span=0x{target.span:X} "
            f"funcs={target.function_count} refs={len(aggregate.hits)} "
            f"avg-score={aggregate.average_score * 100:.2f} "
            f"best={aggregate.best_score * 100:.2f}"
        )
        print(f"      {describe_target_split_overlap(version, target.start, target.end)}")
        for hit in aggregate.hits:
            result = hit.result
            print(
                f"      ref={hit.reference.game} {hit.reference.source_path} "
                f"score={result.overall_score * 100:.2f} "
                f"mask-fn={result.function_mask_score * 100:.2f} "
                f"mask-win={result.window_mask_score * 100:.2f} "
                f"size={result.size_score * 100:.2f} "
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
        "--aggregate-reference-source",
        action="store_true",
        help=(
            "With --reference-source, aggregate repeated target windows across multiple "
            "reference games instead of requiring exactly one --reference"
        ),
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Bulk-scan reference windows against a target SFA range",
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
    parser.add_argument(
        "--only-unassigned",
        action="store_true",
        help="Restrict discovery/reference scans to SFA windows with no current split overlap",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.80,
        help="Minimum score for --discover output, as a 0-1 value",
    )
    parser.add_argument(
        "--limit-per-reference",
        type=int,
        default=1,
        help="Maximum candidate SFA windows to keep per reference split in --discover mode",
    )
    parser.add_argument(
        "--coarse-limit",
        type=int,
        default=4,
        help="Cheap size-shape shortlist size before expensive signature comparison",
    )
    parser.add_argument(
        "--min-functions",
        type=int,
        default=4,
        help="Minimum reference function count to include in --discover mode",
    )
    parser.add_argument(
        "--min-span",
        type=parse_int,
        default=0x100,
        help="Minimum reference text span to include in --discover mode",
    )
    parser.add_argument(
        "--min-largest-function",
        type=parse_int,
        default=0,
        help="Minimum size of the largest function in a candidate window for --discover mode",
    )
    parser.add_argument("--limit", type=int, default=20, help="Number of matches to show")
    args = parser.parse_args()

    if not args.reference:
        args.reference = [parse_reference_spec(value) for value in DEFAULT_REFERENCE_SPECS]

    source_mode = args.source is not None or args.range_start is not None or args.range_end is not None
    reference_mode = args.reference_source is not None
    discover_mode = args.discover
    active_modes = sum((1 if source_mode else 0, 1 if reference_mode else 0, 1 if discover_mode else 0))
    if active_modes != 1:
        parser.error(
            "Choose exactly one mode: either --source/--range-start+--range-end, "
            "--reference-source, or --discover"
        )
    if (args.range_start is None) != (args.range_end is None):
        parser.error("--range-start and --range-end must be provided together")
    if args.range_start is not None and args.range_end <= args.range_start:
        parser.error("--range-end must be greater than --range-start")
    if args.aggregate_reference_source and args.reference_source is None:
        parser.error("--aggregate-reference-source requires --reference-source")
    if (
        args.reference_source is not None
        and not args.aggregate_reference_source
        and len(args.reference) != 1
    ):
        parser.error(
            "--reference-source mode requires exactly one --reference unless "
            "--aggregate-reference-source is used"
        )
    if args.discover and (args.target_range_start is None or args.target_range_end is None):
        parser.error("--discover requires --target-range-start and --target-range-end")
    if args.target_range_start is not None and args.target_range_end is not None:
        if args.target_range_end <= args.target_range_start:
            parser.error("--target-range-end must be greater than --target-range-start")
    if (args.target_range_start is None) != (args.target_range_end is None):
        parser.error("--target-range-start and --target-range-end must be provided together")
    return args


def main() -> None:
    args = parse_args()
    dol_path = target_dol_path_for_version(args.version)

    if args.discover:
        if args.all_splits:
            path_filters = tuple(args.path_contains)
        else:
            path_filters = tuple(args.path_contains) or DEFAULT_SDK_FILTERS
        references: list[RawWindow] = []
        for spec in args.reference:
            references.extend(
                collect_reference_raw_windows(
                    spec,
                    path_filters,
                    min_functions=args.min_functions,
                    min_span=args.min_span,
                    min_largest_function=args.min_largest_function,
                )
            )
        if not references:
            raise SystemExit("No reference windows matched the requested filters")
        hits = discover_reference_hits(
            version=args.version,
            dol_path=dol_path,
            references=references,
            range_start=args.target_range_start,
            range_end=args.target_range_end,
            min_score=args.min_score,
            limit=args.limit,
            limit_per_reference=args.limit_per_reference,
            only_unassigned=args.only_unassigned,
            coarse_limit=args.coarse_limit,
            min_functions=args.min_functions,
            min_span=args.min_span,
            min_largest_function=args.min_largest_function,
        )
        print_discovery_hits(
            version=args.version,
            range_start=args.target_range_start,
            range_end=args.target_range_end,
            only_unassigned=args.only_unassigned,
            min_score=args.min_score,
            hits=hits,
        )
        return

    if args.reference_source is not None:
        if args.aggregate_reference_source:
            aggregates, missing_specs = aggregate_reference_source_matches(
                version=args.version,
                dol_path=dol_path,
                specs=args.reference,
                source_query=args.reference_source,
                target_range_start=args.target_range_start,
                target_range_end=args.target_range_end,
                only_unassigned=args.only_unassigned,
                coarse_limit=args.coarse_limit,
                limit_per_reference=args.limit_per_reference,
                limit=args.limit,
            )
            print_aggregated_reference_source_matches(
                version=args.version,
                source_query=args.reference_source,
                range_start=args.target_range_start,
                range_end=args.target_range_end,
                only_unassigned=args.only_unassigned,
                specs=args.reference,
                aggregates=aggregates,
                missing_specs=missing_specs,
            )
            return

        spec = args.reference[0]
        reference_window = select_reference_window(spec, args.reference_source)
        candidates = list(
            iter_target_windows(
                version=args.version,
                dol_path=dol_path,
                function_count=reference_window.function_count,
                range_start=args.target_range_start,
                range_end=args.target_range_end,
                only_unassigned=args.only_unassigned,
            )
        )
        if not candidates:
            raise SystemExit("No SFA target windows available for the requested search")
        results = rank_candidates(reference_window, candidates, args.limit, args.coarse_limit)
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
            print(
                f"      {describe_target_split_overlap(args.version, candidate.start, candidate.end)}"
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

    results = rank_candidates(target_window, candidates, args.limit, args.coarse_limit)
    print_match_results(target_window, results)


if __name__ == "__main__":
    main()
