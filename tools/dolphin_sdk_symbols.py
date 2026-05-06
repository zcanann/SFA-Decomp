from __future__ import annotations

import argparse
import re
from bisect import bisect_left
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


DOLPHIN_LINE_RE = re.compile(
    r"^(?P<address>[0-9A-Fa-f]{8})\s+"
    r"(?P<size>[0-9A-Fa-f]{6})\s+"
    r"(?P<virtual>[0-9A-Fa-f]{8})\s+\d+\s+"
    r"(?P<payload>.+)$"
)
CONFIG_SYMBOL_RE = re.compile(
    r"^(?P<name>\S+)\s*=\s*(?P<section>\S+):0x(?P<address>[0-9A-Fa-f]+);"
    r"(?:\s*//\s*(?P<meta>.*))?$"
)
SIZE_RE = re.compile(r"\bsize:0x([0-9A-Fa-f]+)\b")
SPLIT_HEADER_RE = re.compile(r"^(?P<path>[^\s].*?):(?:\s+.*)?$")
SPLIT_SECTION_RE = re.compile(
    r"^\s+(?P<section>\S+)\s+start:0x(?P<start>[0-9A-Fa-f]+)\s+end:0x(?P<end>[0-9A-Fa-f]+)"
)

ANONYMOUS_PREFIXES = ("zz_", "fn_", "FUN_", "lbl_", "sub_", "@")
PLACEHOLDER_PREFIXES = ("fn_", "FUN_", "lbl_", "sub_", "zz_")
SPAM_NAMES = {
    "CBGetBytesAvailableForRead",
    "DBClose",
    "gdev_cc_shutdown",
    "IPCGetBufferLo",
    "IPCSetBufferLo",
    "WPADGetDpdSensitivity",
}
SPAM_OBJECTS = {
    ("NdevExi2A.a", "DebuggerDriver.o"),
    (
        "TRK_Hollywood_Revolution.a",
        r"C:\products\RVL\runtime_libs\gamedev\cust_connection\cc\exi2\GCN\EXI2_GDEV_GCN\mai",
    ),
    (
        "TRK_Hollywood_Revolution.a",
        r"C:\products\RVL\runtime_libs\gamedev\cust_connection\utils\common\Circle",
    ),
}
ENTRY_SUFFIX_RE = re.compile(r"\s+\(entry of [^)]+\)$")


@dataclass(frozen=True)
class DolphinSymbol:
    line_number: int
    section: str
    address: int
    size: int
    name: str
    library: str
    object_path: str
    extra: str


@dataclass(frozen=True)
class ConfigSymbol:
    name: str
    section: str
    address: int
    size: int | None
    meta: str


@dataclass(frozen=True)
class SplitRange:
    path: str
    section: str
    start: int
    end: int


@dataclass(frozen=True)
class AddressAnchor:
    section: str
    dolphin_address: int
    config_address: int
    delta: int
    name: str


@dataclass(frozen=True)
class Candidate:
    symbol: DolphinSymbol
    translated_address: int
    translation_delta: int | None
    translation_anchor: AddressAnchor | None
    score: int
    reasons: tuple[str, ...]
    exact: ConfigSymbol | None
    cover: ConfigSymbol | None
    split: SplitRange | None

    @property
    def status(self) -> str:
        symbol_name = comparable_symbol_name(self.symbol.name)
        if self.exact is not None:
            if self.exact.name == symbol_name:
                return "matched"
            if is_placeholder(self.exact.name):
                return "rename"
            return "conflict"
        if self.cover is not None:
            if is_placeholder(self.cover.name):
                return "split-placeholder"
            return "inside-symbol"
        if self.split is not None:
            return "inside-split"
        return "new"


@dataclass(frozen=True)
class TranslatedSymbol:
    symbol: DolphinSymbol
    translated_address: int
    translation_delta: int | None
    translation_anchor: AddressAnchor | None
    exact: ConfigSymbol | None
    cover: ConfigSymbol | None
    split: SplitRange | None


@dataclass(frozen=True)
class SourceCluster:
    source_path: Path
    split_path: str
    candidates: tuple[TranslatedSymbol, ...]
    dominant_library: str
    dominant_object_path: str
    dominant_count: int
    unique_name_count: int
    exact_name_count: int
    active_count: int
    score: int

    @property
    def start(self) -> int:
        return self.candidates[0].translated_address

    @property
    def end(self) -> int:
        last = self.candidates[-1]
        return last.translated_address + last.symbol.size

    @property
    def span(self) -> int:
        return self.end - self.start


def default_dolphin_path(version: str) -> Path:
    candidates = [
        Path("resources") / f"DolphinSymbolExport_{version}.txt",
        Path("resources") / f"DolphinSymbolExtract_{version}.txt",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    tried = ", ".join(str(candidate) for candidate in candidates)
    raise SystemExit(f"Missing Dolphin symbol export for {version}: tried {tried}")


def parse_lib_and_object(extra: str) -> tuple[str, str]:
    if not extra:
        return "", ""
    parts = extra.split()
    if not parts:
        return "", ""
    library = parts[0]
    object_path = parts[1] if len(parts) > 1 else ""
    return library, object_path


def load_dolphin_symbols(path: Path) -> list[DolphinSymbol]:
    symbols: list[DolphinSymbol] = []
    section = ""
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="ignore").splitlines(),
        start=1,
    ):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith("section layout"):
            section = stripped.split()[0]
            continue

        match = DOLPHIN_LINE_RE.match(stripped)
        if match is None:
            continue

        payload = match.group("payload")
        payload_parts = [part.strip() for part in payload.split("\t")]
        name = payload_parts[0]
        extra = " ".join(part for part in payload_parts[1:] if part)
        library, object_path = parse_lib_and_object(extra)
        symbols.append(
            DolphinSymbol(
                line_number=line_number,
                section=section,
                address=int(match.group("address"), 16),
                size=int(match.group("size"), 16),
                name=name,
                library=library,
                object_path=object_path,
                extra=extra,
            )
        )
    return symbols


def load_config_symbols(path: Path) -> list[ConfigSymbol]:
    symbols: list[ConfigSymbol] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = CONFIG_SYMBOL_RE.match(line.strip())
        if match is None:
            continue

        meta = match.group("meta") or ""
        size_match = SIZE_RE.search(meta)
        symbols.append(
            ConfigSymbol(
                name=match.group("name"),
                section=match.group("section"),
                address=int(match.group("address"), 16),
                size=int(size_match.group(1), 16) if size_match else None,
                meta=meta,
            )
        )
    return symbols


def load_splits(path: Path) -> list[SplitRange]:
    ranges: list[SplitRange] = []
    current_path = ""
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        header_match = SPLIT_HEADER_RE.match(line)
        if header_match is not None and not line.startswith("\t") and line != "Sections:":
            current_path = header_match.group("path")
            continue

        section_match = SPLIT_SECTION_RE.match(line)
        if section_match is None or not current_path:
            continue

        ranges.append(
            SplitRange(
                path=current_path,
                section=section_match.group("section"),
                start=int(section_match.group("start"), 16),
                end=int(section_match.group("end"), 16),
            )
        )
    return ranges


SOURCE_FUNCTION_RE = re.compile(
    r"^(?:asm\s+)?(?:static\s+)?(?:inline\s+)?"
    r"(?:[\w:~*<>\[\]\s]+?\s+)?(?P<name>[A-Za-z_~]\w*(?:::\w+)*)\s*\([^;]*\)\s*(?:\{|$)"
)
CONTROL_KEYWORDS = {"if", "for", "while", "switch"}


def load_source_function_names(path: Path) -> set[str]:
    names: set[str] = set()
    pending_name: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//") or line.startswith("#"):
            continue

        if pending_name is not None:
            if line.startswith("{"):
                names.add(pending_name)
            pending_name = None

        match = SOURCE_FUNCTION_RE.match(line)
        if match is not None:
            name = match.group("name")
            if name in CONTROL_KEYWORDS:
                continue
            if "{" in line:
                names.add(name)
            elif not line.endswith(";"):
                pending_name = name
    return names


def is_anonymous(name: str) -> bool:
    return comparable_symbol_name(name).startswith(ANONYMOUS_PREFIXES)


def is_placeholder(name: str) -> bool:
    return name.startswith(PLACEHOLDER_PREFIXES)


def comparable_symbol_name(name: str) -> str:
    return ENTRY_SUFFIX_RE.sub("", name)


def sanitize_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "unknown"


def suggest_source_path(candidate: Candidate) -> str:
    library = candidate.symbol.library
    object_path = candidate.symbol.object_path
    object_base = Path(object_path).stem if object_path else "unknown"
    object_name = sanitize_component(object_base)

    if library == "Runtime.PPCEABI.H.a":
        return f"Runtime.PPCEABI.H/{object_name}.s"

    lib_name = sanitize_component(library.removesuffix(".a"))
    extension = ".cpp" if "::" in candidate.symbol.name else ".c"
    return f"sdk/{lib_name}/{object_name}{extension}"


def source_match_names(
    symbol: DolphinSymbol,
    exact: ConfigSymbol | None,
) -> tuple[str, ...]:
    names: list[str] = []
    symbol_name = comparable_symbol_name(symbol.name)
    if exact is not None and not is_placeholder(exact.name):
        names.append(exact.name)
        if exact.name != symbol_name:
            return tuple(names)
    if not is_anonymous(symbol_name) and symbol_name not in names:
        names.append(symbol_name)
    return tuple(names)


def preferred_match_name(item: TranslatedSymbol) -> str:
    if item.exact is not None and not is_placeholder(item.exact.name):
        return item.exact.name
    return comparable_symbol_name(item.symbol.name)


def build_symbol_indexes(
    symbols: list[ConfigSymbol],
) -> tuple[dict[tuple[str, int], ConfigSymbol], dict[str, list[ConfigSymbol]], dict[str, list[ConfigSymbol]]]:
    by_address = {(symbol.section, symbol.address): symbol for symbol in symbols}
    by_section: dict[str, list[ConfigSymbol]] = defaultdict(list)
    by_name: dict[str, list[ConfigSymbol]] = defaultdict(list)
    for symbol in symbols:
        by_section[symbol.section].append(symbol)
        by_name[symbol.name].append(symbol)
    for section_symbols in by_section.values():
        section_symbols.sort(key=lambda symbol: symbol.address)
    return by_address, by_section, by_name


def build_address_anchors(
    dolphin_symbols: list[DolphinSymbol],
    config_symbols_by_name: dict[str, list[ConfigSymbol]],
) -> list[AddressAnchor]:
    anchors: list[AddressAnchor] = []
    for dolphin_symbol in dolphin_symbols:
        symbol_name = comparable_symbol_name(dolphin_symbol.name)
        if is_anonymous(symbol_name):
            continue

        config_matches = config_symbols_by_name.get(symbol_name)
        if config_matches is None or len(config_matches) != 1:
            continue

        config_symbol = config_matches[0]
        if config_symbol.section != dolphin_symbol.section:
            continue
        if is_placeholder(config_symbol.name):
            continue
        if config_symbol.size is not None and config_symbol.size != dolphin_symbol.size:
            continue

        delta = config_symbol.address - dolphin_symbol.address
        if abs(delta) > 0x2000:
            continue

        anchors.append(
            AddressAnchor(
                section=dolphin_symbol.section,
                dolphin_address=dolphin_symbol.address,
                config_address=config_symbol.address,
                delta=delta,
                name=symbol_name,
            )
        )

    anchors.sort(key=lambda anchor: (anchor.section, anchor.dolphin_address, anchor.name))
    return anchors


def build_anchor_indexes(
    anchors: list[AddressAnchor],
) -> dict[str, tuple[list[int], list[AddressAnchor]]]:
    by_section: dict[str, list[AddressAnchor]] = defaultdict(list)
    for anchor in anchors:
        by_section[anchor.section].append(anchor)

    indexed: dict[str, tuple[list[int], list[AddressAnchor]]] = {}
    for section, section_anchors in by_section.items():
        section_anchors.sort(key=lambda anchor: anchor.dolphin_address)
        indexed[section] = (
            [anchor.dolphin_address for anchor in section_anchors],
            section_anchors,
        )
    return indexed


def find_translation_anchor(
    anchor_indexes: dict[str, tuple[list[int], list[AddressAnchor]]],
    section: str,
    address: int,
) -> AddressAnchor | None:
    section_index = anchor_indexes.get(section)
    if section_index is None:
        return None

    dolphin_addresses, anchors = section_index
    insertion = bisect_left(dolphin_addresses, address)
    neighbors: list[AddressAnchor] = []
    if insertion > 0:
        neighbors.append(anchors[insertion - 1])
    if insertion < len(anchors):
        neighbors.append(anchors[insertion])
    if not neighbors:
        return None

    return min(neighbors, key=lambda anchor: abs(anchor.dolphin_address - address))


def translate_address(
    symbol: DolphinSymbol,
    anchor_indexes: dict[str, tuple[list[int], list[AddressAnchor]]],
    manual_delta: int | None,
) -> tuple[int, int | None, AddressAnchor | None]:
    if manual_delta is not None:
        return symbol.address + manual_delta, manual_delta, None

    anchor = find_translation_anchor(anchor_indexes, symbol.section, symbol.address)
    if anchor is None:
        return symbol.address, None, None
    return symbol.address + anchor.delta, anchor.delta, anchor


def find_covering_symbol(
    symbols_by_section: dict[str, list[ConfigSymbol]],
    section: str,
    address: int,
) -> ConfigSymbol | None:
    section_symbols = symbols_by_section.get(section)
    if not section_symbols:
        return None

    last_symbol: ConfigSymbol | None = None
    for symbol in section_symbols:
        if symbol.address > address:
            break
        last_symbol = symbol

    if last_symbol is None:
        return None
    if last_symbol.size is None:
        return last_symbol
    if address < last_symbol.address + last_symbol.size:
        return last_symbol
    return None


def find_split(ranges: list[SplitRange], section: str, address: int) -> SplitRange | None:
    for split_range in ranges:
        if split_range.section == section and split_range.start <= address < split_range.end:
            return split_range
    return None


def score_symbol(
    symbol: DolphinSymbol,
    occurrences: Counter[str],
    exact: ConfigSymbol | None,
    cover: ConfigSymbol | None,
    split_range: SplitRange | None,
) -> tuple[int, tuple[str, ...]]:
    score = 0
    reasons: list[str] = []

    if symbol.library:
        score += 2
        reasons.append("library")
    if symbol.object_path:
        score += 1
        reasons.append("object")
    if symbol.size > 8:
        score += 1
        reasons.append("size>8")
    if symbol.size > 0x20:
        score += 1
        reasons.append("size>0x20")

    symbol_name = comparable_symbol_name(symbol.name)
    count = occurrences[symbol_name]
    if count == 1:
        score += 2
        reasons.append("unique")
    else:
        penalty = min(3, count - 1)
        score -= penalty
        reasons.append(f"repeated:{count}")

    if exact is not None:
        if exact.name == comparable_symbol_name(symbol.name):
            score += 3
            reasons.append("exact-match")
        elif is_placeholder(exact.name):
            score += 2
            reasons.append("exact-placeholder")
        else:
            score -= 1
            reasons.append("exact-conflict")
    elif cover is not None:
        if is_placeholder(cover.name):
            score += 2
            reasons.append("covered-by-placeholder")
        else:
            score -= 1
            reasons.append("covered-by-symbol")
    elif split_range is None:
        score += 1
        reasons.append("outside-splits")

    if symbol_name in SPAM_NAMES:
        score -= 3
        reasons.append("spam-name")
    if (symbol.library, symbol.object_path) in SPAM_OBJECTS:
        score -= 5
        reasons.append("spam-object")
    if symbol.size <= 8:
        score -= 2
        reasons.append("tiny")

    return score, tuple(reasons)


def build_candidates(
    translated_symbols: list[TranslatedSymbol],
) -> list[Candidate]:
    occurrences = Counter(
        comparable_symbol_name(item.symbol.name)
        for item in translated_symbols
        if not is_anonymous(item.symbol.name)
    )
    candidates: list[Candidate] = []

    for item in translated_symbols:
        symbol = item.symbol
        if is_anonymous(symbol.name):
            continue

        score, reasons = score_symbol(
            symbol,
            occurrences,
            item.exact,
            item.cover,
            item.split,
        )
        candidates.append(
            Candidate(
                symbol=symbol,
                translated_address=item.translated_address,
                translation_delta=item.translation_delta,
                translation_anchor=item.translation_anchor,
                score=score,
                reasons=reasons,
                exact=item.exact,
                cover=item.cover,
                split=item.split,
            )
        )

    candidates.sort(key=lambda candidate: (-candidate.score, candidate.symbol.address, candidate.symbol.name))
    return candidates


def build_translated_symbols(
    dolphin_symbols: list[DolphinSymbol],
    config_symbols: list[ConfigSymbol],
    split_ranges: list[SplitRange],
    manual_delta: int | None,
) -> list[TranslatedSymbol]:
    by_address, by_section, by_name = build_symbol_indexes(config_symbols)
    anchors = build_address_anchors(dolphin_symbols, by_name)
    anchor_indexes = build_anchor_indexes(anchors)
    translated_symbols: list[TranslatedSymbol] = []

    for symbol in dolphin_symbols:
        translated_address, translation_delta, translation_anchor = translate_address(
            symbol, anchor_indexes, manual_delta
        )
        exact = by_address.get((symbol.section, translated_address))
        cover = None if exact is not None else find_covering_symbol(
            by_section, symbol.section, translated_address
        )
        split_range = find_split(split_ranges, symbol.section, translated_address)
        translated_symbols.append(
            TranslatedSymbol(
                symbol=symbol,
                translated_address=translated_address,
                translation_delta=translation_delta,
                translation_anchor=translation_anchor,
                exact=exact,
                cover=cover,
                split=split_range,
            )
        )

    return translated_symbols


def has_provenance(symbol: DolphinSymbol) -> bool:
    return bool(symbol.library and symbol.object_path)


def translated_range(
    symbols: list[DolphinSymbol],
    start_index: int,
    end_index: int,
    anchor_indexes: dict[str, tuple[list[int], list[AddressAnchor]]],
    manual_delta: int | None,
) -> tuple[int, int]:
    start_symbol = symbols[start_index]
    end_symbol = symbols[end_index]
    translated_start, _, _ = translate_address(start_symbol, anchor_indexes, manual_delta)
    translated_end, _, _ = translate_address(end_symbol, anchor_indexes, manual_delta)
    return translated_start, translated_end + end_symbol.size


def infer_object_span(
    translated_symbols: list[TranslatedSymbol],
    library: str,
    object_path: str,
    source_functions: set[str] | None,
) -> tuple[int, int]:
    anchor_indices = [
        index
        for index, item in enumerate(translated_symbols)
        if item.symbol.library == library and item.symbol.object_path == object_path
    ]
    if not anchor_indices:
        raise SystemExit(f"No Dolphin symbols found for {library} {object_path}")

    first_anchor = anchor_indices[0]
    last_anchor = anchor_indices[-1]

    end_index = last_anchor
    for index in range(last_anchor + 1, len(translated_symbols)):
        if has_provenance(translated_symbols[index].symbol):
            break
        end_index = index

    start_index = first_anchor
    if source_functions:
        for index in range(first_anchor, -1, -1):
            item = translated_symbols[index]
            symbol = item.symbol
            if has_provenance(symbol) and index not in anchor_indices:
                break
            if any(name in source_functions for name in source_match_names(symbol, item.exact)):
                start_index = index

    return start_index, end_index


def print_object_span(
    translated_symbols: list[TranslatedSymbol],
    library: str,
    object_path: str,
    source_path: Path | None,
) -> None:
    source_functions = load_source_function_names(source_path) if source_path else None
    start_index, end_index = infer_object_span(
        translated_symbols,
        library,
        object_path,
        source_functions,
    )
    translated_start = translated_symbols[start_index].translated_address
    translated_end = (
        translated_symbols[end_index].translated_address + translated_symbols[end_index].symbol.size
    )

    print(f"# {library} {object_path}")
    if source_path is not None:
        print(f"# source={source_path}")
    print(
        f"# export-lines={translated_symbols[start_index].symbol.line_number}-"
        f"{translated_symbols[end_index].symbol.line_number} "
        f"count={end_index - start_index + 1}"
    )
    print(
        f"# translated .text span start=0x{translated_start:08X} end=0x{translated_end:08X} "
        f"size=0x{translated_end - translated_start:X}"
    )
    print()

    for index in range(start_index, end_index + 1):
        item = translated_symbols[index]
        symbol = item.symbol
        anchor_text = "-"
        if item.translation_anchor is not None:
            anchor_text = f"{item.translation_anchor.name}@0x{item.translation_anchor.dolphin_address:08X}"
        exact_text = item.exact.name if item.exact is not None else "-"
        split_text = item.split.path if item.split is not None else "-"
        print(
            f"0x{symbol.address:08X} -> 0x{item.translated_address:08X} "
            f"size=0x{symbol.size:X} name={symbol.name}"
        )
        print(
            f"  line={symbol.line_number} delta={format_signed_hex(item.translation_delta or 0)} "
            f"anchor={anchor_text}"
        )
        print(f"  exact={exact_text} split={split_text}")


def is_actionable(
    candidate: Candidate,
    min_score: int,
    text_only: bool,
    require_provenance: bool,
) -> bool:
    symbol = candidate.symbol
    if text_only and symbol.section != ".text":
        return False
    if candidate.score < min_score:
        return False
    if require_provenance and (not symbol.library or not symbol.object_path):
        return False
    return True


def print_summary(
    candidates: list[Candidate],
    dolphin_path: Path,
    min_score: int,
    require_provenance: bool,
    anchors: list[AddressAnchor],
) -> None:
    total = len(candidates)
    actionable = [
        candidate
        for candidate in candidates
        if is_actionable(candidate, min_score, False, require_provenance)
    ]
    text_actionable = [
        candidate
        for candidate in candidates
        if is_actionable(candidate, min_score, True, require_provenance)
    ]
    with_provenance = [
        candidate
        for candidate in actionable
        if candidate.symbol.library and candidate.symbol.object_path
    ]

    status_counts = Counter(candidate.status for candidate in actionable)
    lib_counts = Counter(
        candidate.symbol.library for candidate in actionable if candidate.symbol.library
    )
    object_counts = Counter(
        (candidate.symbol.library, candidate.symbol.object_path)
        for candidate in actionable
        if candidate.symbol.library and candidate.symbol.object_path
    )

    print(f"Dolphin file: {dolphin_path}")
    print(
        f"Candidates: total={total} actionable={len(actionable)} "
        f"actionable_text={len(text_actionable)} min_score={min_score} "
        f"require_provenance={require_provenance}"
    )
    if anchors:
        delta_counts = Counter(anchor.delta for anchor in anchors)
        print("Address translation anchors:")
        print(f"  total anchors: {len(anchors)}")
        for delta, count in delta_counts.most_common(5):
            print(f"  delta {format_signed_hex(delta):>8} count={count}")
    print("Actionable status counts:")
    for status, count in status_counts.most_common():
        print(f"  {status:18} {count}")

    print("Top actionable libraries:")
    for library, count in lib_counts.most_common(10):
        print(f"  {count:4} {library}")

    print("Top actionable library/object pairs:")
    for (library, object_path), count in object_counts.most_common(10):
        print(f"  {count:4} {library} {object_path}")

    print("Sample actionable candidates:")
    for candidate in with_provenance[:10]:
        symbol = candidate.symbol
        print(
            f"  0x{symbol.address:08X} size=0x{symbol.size:X} score={candidate.score:2} "
            f"-> 0x{candidate.translated_address:08X} {symbol.name} "
            f"[{symbol.library} {symbol.object_path}] status={candidate.status}"
        )


def format_signed_hex(value: int) -> str:
    sign = "+" if value >= 0 else "-"
    return f"{sign}0x{abs(value):X}"


def print_candidates(
    candidates: list[Candidate],
    min_score: int,
    text_only: bool,
    require_provenance: bool,
    library_filter: str | None,
    object_filter: str | None,
    name_filter: str | None,
    limit: int | None,
) -> None:
    shown = 0
    for candidate in candidates:
        symbol = candidate.symbol
        if not is_actionable(candidate, min_score, text_only, require_provenance):
            continue
        if library_filter and symbol.library != library_filter:
            continue
        if object_filter and symbol.object_path != object_filter:
            continue
        if name_filter and name_filter not in symbol.name:
            continue

        cover_text = "-"
        if candidate.cover is not None:
            cover_text = f"{candidate.cover.name}@0x{candidate.cover.address:08X}"
        exact_text = candidate.exact.name if candidate.exact is not None else "-"
        split_text = candidate.split.path if candidate.split is not None else "-"
        provenance = f"{symbol.library} {symbol.object_path}".strip()

        print(
            f"0x{symbol.address:08X} size=0x{symbol.size:X} score={candidate.score:2} "
            f"status={candidate.status:17} name={symbol.name}"
        )
        print(
            f"  translated: 0x{candidate.translated_address:08X} "
            f"(delta {format_signed_hex(candidate.translation_delta or 0)})"
        )
        if candidate.translation_anchor is not None:
            print(
                f"  anchor: {candidate.translation_anchor.name}"
                f"@0x{candidate.translation_anchor.dolphin_address:08X}"
            )
        print(f"  provenance: {provenance or '-'}")
        print(f"  exact: {exact_text}")
        print(f"  cover: {cover_text}")
        print(f"  split: {split_text}")
        print(f"  reasons: {', '.join(candidate.reasons)}")

        shown += 1
        if limit is not None and shown >= limit:
            break


def print_split_seeds(
    candidates: list[Candidate],
    min_score: int,
    require_provenance: bool,
    gap: int,
    min_count: int,
    limit: int | None,
) -> None:
    grouped: dict[tuple[str, str], list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        symbol = candidate.symbol
        if not is_actionable(candidate, min_score, True, require_provenance):
            continue
        if not symbol.library or not symbol.object_path:
            continue
        if candidate.split is not None:
            continue
        if symbol.size <= 8:
            continue
        if (symbol.library, symbol.object_path) in SPAM_OBJECTS:
            continue
        grouped[(symbol.library, symbol.object_path)].append(candidate)

    emitted = 0
    for (library, object_path), items in sorted(grouped.items()):
        items.sort(key=lambda candidate: candidate.symbol.address)
        clusters: list[list[Candidate]] = []
        current: list[Candidate] = []

        for candidate in items:
            if not current:
                current = [candidate]
                continue
            previous = current[-1].symbol
            if candidate.symbol.address <= previous.address + previous.size + gap:
                current.append(candidate)
            else:
                clusters.append(current)
                current = [candidate]
        if current:
            clusters.append(current)

        for cluster in clusters:
            if len(cluster) < min_count:
                continue

            start = cluster[0].translated_address
            end = cluster[-1].translated_address + cluster[-1].symbol.size
            seed_path = suggest_source_path(cluster[0])
            names = ", ".join(candidate.symbol.name for candidate in cluster[:5])
            if len(cluster) > 5:
                names += ", ..."

            print(f"# {library} {object_path}")
            print(
                f"# count={len(cluster)} span=0x{end - start:X} "
                f"score={max(candidate.score for candidate in cluster)} names={names}"
            )
            print(f"{seed_path}:")
            print(f"\t.text       start:0x{start:08X} end:0x{end:08X}")
            print()

            emitted += 1
            if limit is not None and emitted >= limit:
                return


SOURCE_SUFFIXES = {".c", ".cc", ".cp", ".cpp", ".cxx", ".s"}


def iter_source_paths(src_root: Path) -> list[Path]:
    return sorted(
        path
        for path in src_root.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
    )


def cluster_source_candidates(
    source_path: Path,
    src_root: Path,
    seed_index: dict[str, list[TranslatedSymbol]],
    all_index: dict[str, list[TranslatedSymbol]],
    gap: int,
    require_provenance: bool,
) -> list[SourceCluster]:
    try:
        split_path = source_path.relative_to(src_root).as_posix()
    except ValueError:
        split_path = source_path.as_posix()

    source_functions = load_source_function_names(source_path)
    if not source_functions:
        return []

    matched: list[TranslatedSymbol] = []
    seen: set[tuple[int, str]] = set()
    for name in sorted(source_functions):
        for candidate in seed_index.get(name, []):
            if candidate.symbol.section != ".text":
                continue
            key = (candidate.translated_address, name)
            if key in seen:
                continue
            seen.add(key)
            matched.append(candidate)

    if len(matched) < 2:
        return []

    matched.sort(key=lambda candidate: candidate.translated_address)
    clusters: list[list[TranslatedSymbol]] = []
    current: list[TranslatedSymbol] = []

    for candidate in matched:
        if not current:
            current = [candidate]
            continue

        previous = current[-1]
        if candidate.translated_address <= previous.translated_address + previous.symbol.size + gap:
            current.append(candidate)
        else:
            clusters.append(current)
            current = [candidate]

    if current:
        clusters.append(current)

    all_matches: list[TranslatedSymbol] = []
    seen_matches: set[tuple[int, str]] = set()
    for name in sorted(source_functions):
        for candidate in all_index.get(name, []):
            if candidate.symbol.section != ".text":
                continue
            key = (candidate.translated_address, name)
            if key in seen_matches:
                continue
            seen_matches.add(key)
            all_matches.append(candidate)
    all_matches.sort(key=lambda candidate: candidate.translated_address)

    reports: list[SourceCluster] = []
    for cluster in clusters:
        expanded = list(cluster)
        start = min(candidate.translated_address for candidate in expanded)
        end = max(candidate.translated_address + candidate.symbol.size for candidate in expanded)
        expanded_seen = {
            (candidate.translated_address, preferred_match_name(candidate)) for candidate in expanded
        }
        changed = True
        while changed:
            changed = False
            for candidate in all_matches:
                key = (candidate.translated_address, preferred_match_name(candidate))
                if key in expanded_seen:
                    continue
                candidate_start = candidate.translated_address
                candidate_end = candidate_start + candidate.symbol.size
                if candidate_start > end + gap or candidate_end < start - gap:
                    continue
                expanded.append(candidate)
                expanded_seen.add(key)
                start = min(start, candidate_start)
                end = max(end, candidate_end)
                changed = True

        expanded.sort(key=lambda candidate: candidate.translated_address)
        unique_names = {preferred_match_name(candidate) for candidate in expanded}
        if len(unique_names) < 2:
            continue

        provenance_counts = Counter(
            (candidate.symbol.library, candidate.symbol.object_path)
            for candidate in expanded
            if candidate.symbol.library and candidate.symbol.object_path
        )
        if require_provenance and not provenance_counts:
            continue

        dominant_library = ""
        dominant_object_path = ""
        dominant_count = 0
        if provenance_counts:
            (dominant_library, dominant_object_path), dominant_count = provenance_counts.most_common(1)[0]
        if require_provenance and dominant_count < 2:
            continue
        exact_name_count = sum(
            candidate.exact is not None
            and not is_placeholder(candidate.exact.name)
            and candidate.exact.name in source_functions
            for candidate in expanded
        )
        active_count = sum(candidate.split is not None for candidate in expanded)
        split_free_count = len(expanded) - active_count
        score = (
            len(unique_names) * 8
            + dominant_count * 4
            + exact_name_count * 2
            + split_free_count * 2
            - active_count * 4
        )

        reports.append(
            SourceCluster(
                source_path=source_path,
                split_path=split_path,
                candidates=tuple(expanded),
                dominant_library=dominant_library,
                dominant_object_path=dominant_object_path,
                dominant_count=dominant_count,
                unique_name_count=len(unique_names),
                exact_name_count=exact_name_count,
                active_count=active_count,
                score=score,
            )
        )

    reports.sort(
        key=lambda report: (
            -report.score,
            -report.unique_name_count,
            report.start,
            report.split_path,
        )
    )
    return reports


def print_source_clusters(
    candidates: list[Candidate],
    translated_symbols: list[TranslatedSymbol],
    src_root: Path,
    gap: int,
    limit: int | None,
    source_filter: Path | None,
    min_score: int,
    require_provenance: bool,
) -> None:
    seed_keys = {
        (candidate.symbol.section, candidate.translated_address)
        for candidate in candidates
        if candidate.symbol.section == ".text"
        and candidate.translation_delta is not None
        and (
            (
                candidate.exact is not None
                and not is_placeholder(candidate.exact.name)
            )
            or is_actionable(candidate, min_score, True, require_provenance)
        )
        and (
            not require_provenance
            or (candidate.symbol.library and candidate.symbol.object_path)
        )
    }

    seed_index: dict[str, list[TranslatedSymbol]] = defaultdict(list)
    all_index: dict[str, list[TranslatedSymbol]] = defaultdict(list)
    for candidate in translated_symbols:
        if candidate.symbol.section != ".text" or candidate.translation_delta is None:
            continue

        names = source_match_names(candidate.symbol, candidate.exact)
        if not names:
            continue

        for name in names:
            all_index[name].append(candidate)
            key = (candidate.symbol.section, candidate.translated_address)
            if key in seed_keys:
                seed_index[name].append(candidate)

    source_paths = [source_filter] if source_filter is not None else iter_source_paths(src_root)
    reports: list[SourceCluster] = []
    for source_path in source_paths:
        if source_path is None or not source_path.is_file():
            continue
        reports.extend(
            cluster_source_candidates(
                source_path,
                src_root,
                seed_index,
                all_index,
                gap,
                require_provenance,
            )
        )

    reports = [report for report in reports if report.active_count < len(report.candidates)]
    reports.sort(
        key=lambda report: (
            -report.score,
            -report.unique_name_count,
            report.start,
            report.split_path,
        )
    )

    emitted = 0
    for report in reports:
        names = ", ".join(preferred_match_name(candidate) for candidate in report.candidates[:6])
        if len(report.candidates) > 6:
            names += ", ..."

        print(f"# {report.source_path}")
        print(
            f"# split={report.split_path} score={report.score} span=0x{report.span:X} "
            f"matches={len(report.candidates)} unique={report.unique_name_count} "
            f"exact={report.exact_name_count} active={report.active_count}"
        )
        print(
            f"# dominant={report.dominant_library} {report.dominant_object_path} "
            f"count={report.dominant_count}"
        )
        print(f"# names={names}")
        print(f"{report.split_path}:")
        print(f"\t.text       start:0x{report.start:08X} end:0x{report.end:08X}")
        print()

        emitted += 1
        if limit is not None and emitted >= limit:
            return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Filter useful SDK symbol candidates from a Dolphin symbol export."
    )
    parser.add_argument(
        "command",
        choices=["summary", "candidates", "split-seeds", "object-span", "source-clusters"],
        help="Which report to print",
    )
    parser.add_argument(
        "-v",
        "--version",
        default="GSAE01",
        help="Version to inspect (default: GSAE01)",
    )
    parser.add_argument(
        "--dolphin-symbols",
        type=Path,
        help="Explicit Dolphin symbol export path",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=6,
        help="Minimum candidate score to show (default: 6)",
    )
    parser.add_argument(
        "--all-sections",
        action="store_true",
        help="Include non-.text symbols",
    )
    parser.add_argument(
        "--no-provenance-required",
        action="store_true",
        help="Also show candidates without library/object provenance",
    )
    parser.add_argument(
        "--lib",
        help="Filter candidates to an exact library name",
    )
    parser.add_argument(
        "--obj",
        help="Filter candidates to an exact object name/path",
    )
    parser.add_argument(
        "--name",
        help="Substring filter for symbol names",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum rows or clusters to print",
    )
    parser.add_argument(
        "--gap",
        type=lambda value: int(value, 0),
        default=0x100,
        help="Maximum cluster gap for split seeds (default: 0x100)",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=2,
        help="Minimum candidate count per split seed cluster (default: 2)",
    )
    parser.add_argument(
        "--address-delta",
        type=lambda value: int(value, 0),
        help="Manual address delta to apply to Dolphin symbols before matching",
    )
    parser.add_argument(
        "--source",
        type=Path,
        help="Local source file used to infer the start of an object span",
    )
    parser.add_argument(
        "--src-root",
        type=Path,
        default=Path("src"),
        help="Root source directory scanned by source-clusters (default: src)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dolphin_path = args.dolphin_symbols or default_dolphin_path(args.version)
    config_dir = Path("config") / args.version
    symbols_path = config_dir / "symbols.txt"
    splits_path = config_dir / "splits.txt"

    if not symbols_path.is_file():
        raise SystemExit(f"Missing symbols file: {symbols_path}")
    if not splits_path.is_file():
        raise SystemExit(f"Missing splits file: {splits_path}")

    dolphin_symbols = load_dolphin_symbols(dolphin_path)
    config_symbols = load_config_symbols(symbols_path)
    split_ranges = load_splits(splits_path)
    _, _, by_name = build_symbol_indexes(config_symbols)
    anchors = build_address_anchors(dolphin_symbols, by_name)
    translated_symbols = build_translated_symbols(
        dolphin_symbols,
        config_symbols,
        split_ranges,
        args.address_delta,
    )
    candidates = build_candidates(translated_symbols)

    if args.command == "summary":
        print_summary(
            candidates,
            dolphin_path,
            args.min_score,
            not args.no_provenance_required,
            anchors,
        )
    elif args.command == "candidates":
        print_candidates(
            candidates=candidates,
            min_score=args.min_score,
            text_only=not args.all_sections,
            require_provenance=not args.no_provenance_required,
            library_filter=args.lib,
            object_filter=args.obj,
            name_filter=args.name,
            limit=args.limit,
        )
    elif args.command == "split-seeds":
        print_split_seeds(
            candidates=candidates,
            min_score=args.min_score,
            require_provenance=not args.no_provenance_required,
            gap=args.gap,
            min_count=args.min_count,
            limit=args.limit,
        )
    elif args.command == "object-span":
        if not args.lib or not args.obj:
            raise SystemExit("object-span requires --lib and --obj")
        print_object_span(
            translated_symbols=translated_symbols,
            library=args.lib,
            object_path=args.obj,
            source_path=args.source,
        )
    elif args.command == "source-clusters":
        print_source_clusters(
            candidates=candidates,
            translated_symbols=translated_symbols,
            src_root=args.src_root,
            gap=args.gap,
            limit=args.limit,
            source_filter=args.source,
            min_score=args.min_score,
            require_provenance=not args.no_provenance_required,
        )
    else:
        raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
