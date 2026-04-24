from __future__ import annotations

import argparse
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


BLOCK_RE = re.compile(
    r"(?P<prefix>/\*\s*\r?\n\s*\* --INFO--\s*\r?\n\s*\*\s*\r?\n\s*\* Function:\s*)"
    r"(?P<function>[^\r\n]+)"
    r"(?P<mid1>\r?\n\s*\* EN v1\.0 Address:\s*)(?P<v10_addr>[^\r\n]+)"
    r"(?P<mid2>\r?\n\s*\* EN v1\.0 Size:\s*)(?P<v10_size>[^\r\n]+)"
    r"(?P<suffix>"
    r"\r?\n\s*\* EN v1\.1 Address:\s*[^\r\n]+"
    r"\r?\n\s*\* EN v1\.1 Size:\s*[^\r\n]+"
    r"\r?\n\s*\* JP Address:\s*[^\r\n]+"
    r"\r?\n\s*\* JP Size:\s*[^\r\n]+"
    r"\r?\n\s*\* PAL Address:\s*[^\r\n]+"
    r"\r?\n\s*\* PAL Size:\s*[^\r\n]+"
    r"\r?\n\s*\*/)"
)

TEXT_SPLIT_RE = re.compile(r"\t\.text\s+start:0x([0-9A-Fa-f]+)\s+end:0x([0-9A-Fa-f]+)")
SYMBOL_RE = re.compile(r"^([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([tT])\s+(.+)$")
NAME_WITH_ADDR_RE = re.compile(r"^(?:FUN|fn)_([0-9A-Fa-f]{8})$")


@dataclass(frozen=True)
class TextSymbol:
    offset: int
    size: int
    name: str


def parse_splits(path: Path) -> dict[str, int]:
    split_starts: dict[str, int] = {}
    current_path: str | None = None
    for raw_line in path.read_text().splitlines():
        if raw_line and not raw_line.startswith("\t") and raw_line.endswith(":"):
            current_path = raw_line[:-1].replace("\\", "/")
            continue
        match = TEXT_SPLIT_RE.match(raw_line)
        if match and current_path is not None:
            split_starts[f"src/{current_path}"] = int(match.group(1), 16)
    return split_starts


def load_text_symbols(nm_path: Path, obj_path: Path) -> tuple[list[TextSymbol], dict[str, list[TextSymbol]]]:
    result = subprocess.run(
        [str(nm_path), "-n", "-S", str(obj_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    ordered_symbols: list[TextSymbol] = []
    symbols: dict[str, list[TextSymbol]] = defaultdict(list)
    for raw_line in result.stdout.splitlines():
        match = SYMBOL_RE.match(raw_line.strip())
        if match is None:
            continue
        offset = int(match.group(1), 16)
        size = int(match.group(2), 16)
        name = match.group(4).strip()
        if name.startswith("@"):
            continue
        symbol = TextSymbol(offset=offset, size=size, name=name)
        ordered_symbols.append(symbol)
        symbols[name].append(symbol)
    return ordered_symbols, symbols


def format_address(value: int) -> str:
    return f"0x{value:08X}"


def format_size(value: int) -> str:
    return f"{value}b"


def iter_source_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.c") if path.is_file())


def parse_address_from_name(name: str) -> int | None:
    match = NAME_WITH_ADDR_RE.match(name.strip())
    if match is None:
        return None
    return int(match.group(1), 16)


def find_definition_name(source: str, block_end: int) -> str | None:
    tail = source[block_end:]
    window = tail[:2000]
    lines: list[str] = []
    for raw_line in window.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("#pragma"):
            continue
        if stripped.startswith("/*") or stripped.startswith("*") or stripped.startswith("//"):
            continue
        lines.append(stripped)
        if "{" in stripped:
            break
    if not lines:
        return None
    signature = " ".join(lines)
    match = re.search(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", signature)
    if match is None:
        return None
    return match.group(1)


def resolve_obj_path(source_path: Path, source_base: Path, build_root: Path, build_obj_root: Path) -> Path | None:
    rel = source_path.relative_to(source_base).with_suffix(".o")
    primary = build_root / rel
    if primary.exists():
        return primary
    secondary = build_obj_root / rel
    if secondary.exists():
        return secondary
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Populate EN v1.0 comment address/size metadata from current build objects."
    )
    parser.add_argument("--root", type=Path, default=Path("src"), help="Root directory to scan.")
    parser.add_argument(
        "--source-base",
        type=Path,
        default=Path("src"),
        help="Project source root used to map source paths to built objects.",
    )
    parser.add_argument(
        "--splits",
        type=Path,
        default=Path("config/GSAE01/splits.txt"),
        help="Current v1.0 splits file.",
    )
    parser.add_argument(
        "--build-root",
        type=Path,
        default=Path("build/GSAE01/src"),
        help="Build object root for the current v1.0 target.",
    )
    parser.add_argument(
        "--build-obj-root",
        type=Path,
        default=Path("build/GSAE01/obj"),
        help="Fallback object root for linked-false objects in the current v1.0 target.",
    )
    parser.add_argument(
        "--nm",
        type=Path,
        default=Path("build/binutils/powerpc-eabi-nm.exe"),
        help="Path to powerpc-eabi-nm.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report pending updates without modifying files.",
    )
    args = parser.parse_args()

    split_starts = parse_splits(args.splits)

    files_changed = 0
    blocks_changed = 0
    files_with_comments = 0
    skipped_missing_split = 0
    skipped_missing_obj = 0
    skipped_missing_symbol = 0
    skipped_duplicate_symbol = 0

    for source_path in iter_source_files(args.root):
        original = source_path.read_text(encoding="utf-8", errors="ignore")
        if "EN v1.0 Address:" not in original:
            continue
        files_with_comments += 1

        rel = source_path.as_posix()
        split_start = split_starts.get(rel)
        obj_path = resolve_obj_path(source_path, args.source_base, args.build_root, args.build_obj_root)
        if obj_path is None:
            if split_start is None:
                skipped_missing_split += 1
            skipped_missing_obj += 1
            continue
        if split_start is None:
            skipped_missing_split += 1

        ordered_symbols, symbols = load_text_symbols(args.nm, obj_path)
        file_changed = 0
        block_count = len(list(BLOCK_RE.finditer(original)))
        sequential_symbols: list[TextSymbol] | None = None
        sequential_index = 0
        if obj_path.is_relative_to(args.build_obj_root):
            nontrivial_symbols = [symbol for symbol in ordered_symbols if symbol.size > 4]
            if len(nontrivial_symbols) == block_count:
                sequential_symbols = nontrivial_symbols

        def replace(match: re.Match[str]) -> str:
            nonlocal file_changed, blocks_changed, skipped_missing_symbol, skipped_duplicate_symbol
            nonlocal sequential_index

            function_name = match.group("function").strip()
            definition_name = find_definition_name(original, match.end())
            candidate_names: list[str] = []
            if definition_name is not None:
                candidate_names.append(definition_name)
            if function_name not in candidate_names:
                candidate_names.append(function_name)

            candidates: list[TextSymbol] | None = None
            for candidate_name in candidate_names:
                named_candidates = symbols.get(candidate_name)
                if named_candidates is None:
                    continue
                candidates = named_candidates
                break

            if candidates is None:
                if split_start is None and len(symbols) == 1:
                    only_symbol = next(iter(symbols.values()))[0]
                    parsed_address = parse_address_from_name(only_symbol.name)
                    if parsed_address is not None and only_symbol.offset == 0:
                        v10_addr = format_address(parsed_address)
                        v10_size = format_size(only_symbol.size)
                        if (
                            match.group("v10_addr").strip() == v10_addr
                            and match.group("v10_size").strip() == v10_size
                        ):
                            return match.group(0)
                        file_changed += 1
                        blocks_changed += 1
                        return (
                            f"{match.group('prefix')}{function_name}"
                            f"{match.group('mid1')}{v10_addr}"
                            f"{match.group('mid2')}{v10_size}"
                            f"{match.group('suffix')}"
                        )
                if sequential_symbols is not None:
                    symbol = sequential_symbols[sequential_index]
                    sequential_index += 1
                    v10_addr = format_address(split_start + symbol.offset)
                    v10_size = format_size(symbol.size)
                    if (
                        match.group("v10_addr").strip() == v10_addr
                        and match.group("v10_size").strip() == v10_size
                    ):
                        return match.group(0)
                    file_changed += 1
                    blocks_changed += 1
                    return (
                        f"{match.group('prefix')}{function_name}"
                        f"{match.group('mid1')}{v10_addr}"
                        f"{match.group('mid2')}{v10_size}"
                        f"{match.group('suffix')}"
                    )
                skipped_missing_symbol += 1
                return match.group(0)
            if len(candidates) != 1:
                skipped_duplicate_symbol += 1
                return match.group(0)

            symbol = candidates[0]
            if split_start is None:
                parsed_address = parse_address_from_name(symbol.name)
                if parsed_address is None or symbol.offset != 0:
                    skipped_missing_symbol += 1
                    return match.group(0)
                v10_addr = format_address(parsed_address)
                v10_size = format_size(symbol.size)
                if (
                    match.group("v10_addr").strip() == v10_addr
                    and match.group("v10_size").strip() == v10_size
                ):
                    return match.group(0)
                file_changed += 1
                blocks_changed += 1
                return (
                    f"{match.group('prefix')}{function_name}"
                    f"{match.group('mid1')}{v10_addr}"
                    f"{match.group('mid2')}{v10_size}"
                    f"{match.group('suffix')}"
                )
            v10_addr = format_address(split_start + symbol.offset)
            v10_size = format_size(symbol.size)
            if match.group("v10_addr").strip() == v10_addr and match.group("v10_size").strip() == v10_size:
                return match.group(0)

            file_changed += 1
            blocks_changed += 1
            return (
                f"{match.group('prefix')}{function_name}"
                f"{match.group('mid1')}{v10_addr}"
                f"{match.group('mid2')}{v10_size}"
                f"{match.group('suffix')}"
            )

        updated = BLOCK_RE.sub(replace, original)
        if file_changed == 0:
            continue

        files_changed += 1
        if not args.check:
            source_path.write_text(updated, encoding="utf-8", newline="")

    mode = "would update" if args.check else "updated"
    print(f"{mode} {blocks_changed} blocks across {files_changed} files")
    print(f"files_with_comments={files_with_comments}")
    print(
        "skipped_missing_split="
        f"{skipped_missing_split} skipped_missing_obj={skipped_missing_obj} "
        f"skipped_missing_symbol={skipped_missing_symbol} skipped_duplicate_symbol={skipped_duplicate_symbol}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
