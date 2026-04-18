from __future__ import annotations

import argparse
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


SPLIT_HEADER_RE = re.compile(r"^(?P<path>[^\s].*?):(?:\s+.*)?$")
SPLIT_SECTION_RE = re.compile(
    r"^\s+(?P<section>\S+)\s+start:0x(?P<start>[0-9A-Fa-f]+)\s+end:0x(?P<end>[0-9A-Fa-f]+)"
)
CONFIG_SYMBOL_RE = re.compile(
    r"^(?P<name>\S+)\s*=\s*(?P<section>\S+):0x(?P<address>[0-9A-Fa-f]+);"
    r"(?:\s*//\s*(?P<meta>.*))?$"
)
SIZE_RE = re.compile(r"\bsize:0x([0-9A-Fa-f]+)\b")
OBJDUMP_TEXT_RE = re.compile(
    r"^(?P<value>[0-9A-Fa-f]+)\s+\w+\s+(?P<bind>[lgw! ])\s+F\s+\.text\s+"
    r"(?P<size>[0-9A-Fa-f]+)\s+(?P<name>\S+)$"
)
PLACEHOLDER_PREFIXES = ("fn_", "lbl_", "FUN_", "sub_", "zz_")


@dataclass(frozen=True)
class SplitRange:
    path: str
    section: str
    start: int
    end: int


@dataclass(frozen=True)
class ConfigSymbol:
    name: str
    section: str
    address: int
    size: int | None
    meta: str


@dataclass(frozen=True)
class ObjectFunction:
    name: str
    bind: str
    value: int
    size: int


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


def parse_text_symbols(obj_path: Path) -> list[ObjectFunction]:
    result = subprocess.run(
        ["build/binutils/powerpc-eabi-objdump.exe", "-t", str(obj_path)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    functions: list[ObjectFunction] = []
    for line in result.stdout.splitlines():
        match = OBJDUMP_TEXT_RE.match(line.strip())
        if match is None:
            continue
        functions.append(
            ObjectFunction(
                name=match.group("name"),
                bind=match.group("bind").strip() or "?",
                value=int(match.group("value"), 16),
                size=int(match.group("size"), 16),
            )
        )
    return functions


def split_path_for_source(source: Path) -> str:
    rel = source.relative_to("src").as_posix()
    return rel


def object_path_for_source(version: str, source: Path) -> Path:
    return Path("build") / version / source.with_suffix(".o")


def is_placeholder(name: str) -> bool:
    return name.startswith(PLACEHOLDER_PREFIXES)


def find_exact_symbol(symbols_by_addr: dict[int, ConfigSymbol], addr: int) -> ConfigSymbol | None:
    return symbols_by_addr.get(addr)


def find_cover_symbol(symbols: list[ConfigSymbol], addr: int) -> ConfigSymbol | None:
    for symbol in symbols:
        if symbol.section != ".text" or symbol.size is None:
            continue
        if symbol.address < addr < symbol.address + symbol.size:
            return symbol
    return None


def choose_anchor_delta(functions: list[ObjectFunction], split_symbols: list[ConfigSymbol], split_start: int) -> tuple[int, list[tuple[str, int, int]]]:
    current_by_name = {
        symbol.name: symbol
        for symbol in split_symbols
        if symbol.section == ".text" and not is_placeholder(symbol.name)
    }
    anchors: list[tuple[str, int, int]] = []
    for function in functions:
        current = current_by_name.get(function.name)
        if current is None:
            continue
        anchors.append((function.name, function.value, current.address))
    if not anchors:
        return split_start, []
    delta_counts = Counter(current_addr - value for _, value, current_addr in anchors)
    dominant_delta, _ = delta_counts.most_common(1)[0]
    return dominant_delta, anchors


def audit_source(version: str, source: Path, splits: list[SplitRange], symbols: list[ConfigSymbol], only_mismatched: bool) -> None:
    split_path = split_path_for_source(source)
    text_split = next((entry for entry in splits if entry.path == split_path and entry.section == ".text"), None)
    if text_split is None:
        raise SystemExit(f"Missing .text split for {split_path}")

    obj_path = object_path_for_source(version, source)
    if not obj_path.is_file():
        raise SystemExit(f"Missing built object: {obj_path}")

    obj_functions = parse_text_symbols(obj_path)
    symbols_by_addr = {symbol.address: symbol for symbol in symbols if symbol.section == ".text"}
    split_symbols = [
        symbol
        for symbol in symbols
        if symbol.section == ".text" and text_split.start <= symbol.address < text_split.end
    ]
    anchor_delta, anchors = choose_anchor_delta(obj_functions, split_symbols, text_split.start)

    anchor_note = (
        f"anchor-delta=0x{anchor_delta:X} from {len(anchors)} shared names"
        if anchors
        else f"anchor-delta=split-start 0x{text_split.start:X}"
    )
    print(f"{source} -> {split_path} 0x{text_split.start:08X}-0x{text_split.end:08X} ({anchor_note})")
    printed = 0
    for function in obj_functions:
        target_addr = anchor_delta + function.value
        exact = find_exact_symbol(symbols_by_addr, target_addr)
        cover = find_cover_symbol(symbols, target_addr)
        size_match = exact is not None and exact.size == function.size
        if exact is None:
            status = "inside-placeholder" if cover is not None and is_placeholder(cover.name) else "missing"
        elif exact.name == function.name and size_match:
            status = "matched"
        elif is_placeholder(exact.name) and size_match:
            status = "rename"
        else:
            status = "conflict"
        if only_mismatched and status == "matched":
            continue
        extra = ""
        if exact is not None:
            extra = f"current={exact.name}"
            if exact.size is not None:
                extra += f" size=0x{exact.size:X}"
        elif cover is not None:
            extra = f"cover={cover.name}"
        print(
            f"  0x{target_addr:08X} size=0x{function.size:X} bind={function.bind} "
            f"status={status:<18} donor={function.name}"
            + (f" {extra}" if extra else "")
        )
        printed += 1
    if printed == 0:
        print("  no mismatches")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit donor object .text symbols against current SDK split ownership.")
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--only-mismatched", action="store_true")
    parser.add_argument("sources", nargs="+", help="Source file paths under src/")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    source_paths = [Path(path) for path in args.sources]
    splits = load_splits(repo_root / "config" / args.version / "splits.txt")
    symbols = load_config_symbols(repo_root / "config" / args.version / "symbols.txt")
    for source in source_paths:
        audit_source(args.version, source, splits, symbols, args.only_mismatched)


if __name__ == "__main__":
    main()
