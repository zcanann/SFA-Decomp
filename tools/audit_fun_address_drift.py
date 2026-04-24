from __future__ import annotations

import argparse
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


BLOCK_RE = re.compile(
    r"/\*\s*\r?\n\s*\* --INFO--\s*\r?\n\s*\*\s*\r?\n\s*\* Function:\s*(?P<function>[^\r\n]+)"
    r".*?\r?\n\s*\* EN v1\.0 Address:\s*(?P<v10_addr>0x[0-9A-Fa-f]+|TODO)",
    re.S,
)
TEXT_SPLIT_RE = re.compile(r"\t\.text\s+start:0x([0-9A-Fa-f]+)\s+end:0x([0-9A-Fa-f]+)")
SYMBOL_RE = re.compile(r"^([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([tT])\s+(.+)$")
FUN_NAME_RE = re.compile(r"^FUN_([0-9A-Fa-f]+)$")


@dataclass(frozen=True)
class DriftRecord:
    source_path: str
    function_name: str
    suffix_address: int
    actual_address: int
    delta: int
    comment_address: str


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


def load_text_symbols(nm_path: Path, obj_path: Path) -> dict[str, list[int]]:
    result = subprocess.run(
        [str(nm_path), "-n", "-S", str(obj_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    symbols: dict[str, list[int]] = defaultdict(list)
    for raw_line in result.stdout.splitlines():
        match = SYMBOL_RE.match(raw_line.strip())
        if match is None:
            continue
        name = match.group(4).strip()
        if name.startswith("@"):
            continue
        symbols[name].append(int(match.group(1), 16))
    return symbols


def iter_source_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.c") if path.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit FUN_<addr> names whose suffix no longer matches current v1.0 placement."
    )
    parser.add_argument("--root", type=Path, default=Path("src"))
    parser.add_argument("--source-base", type=Path, default=Path("src"))
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"))
    parser.add_argument("--build-root", type=Path, default=Path("build/GSAE01/src"))
    parser.add_argument("--nm", type=Path, default=Path("build/binutils/powerpc-eabi-nm.exe"))
    parser.add_argument("--limit", type=int, default=50, help="Number of detailed records to print.")
    args = parser.parse_args()

    split_starts = parse_splits(args.splits)
    records: list[DriftRecord] = []
    skipped_missing_split = 0
    skipped_missing_obj = 0
    skipped_missing_symbol = 0
    skipped_duplicate_symbol = 0

    for source_path in iter_source_files(args.root):
        text = source_path.read_text(encoding="utf-8", errors="ignore")
        if "Function: FUN_" not in text:
            continue

        rel = source_path.as_posix()
        split_start = split_starts.get(rel)
        if split_start is None:
            skipped_missing_split += 1
            continue

        obj_path = args.build_root / source_path.relative_to(args.source_base)
        obj_path = obj_path.with_suffix(".o")
        if not obj_path.exists():
            skipped_missing_obj += 1
            continue

        symbols = load_text_symbols(args.nm, obj_path)
        for match in BLOCK_RE.finditer(text):
            function_name = match.group("function").strip()
            name_match = FUN_NAME_RE.match(function_name)
            if name_match is None:
                continue

            symbol_offsets = symbols.get(function_name)
            if symbol_offsets is None:
                skipped_missing_symbol += 1
                continue
            if len(symbol_offsets) != 1:
                skipped_duplicate_symbol += 1
                continue

            suffix_address = int(name_match.group(1), 16)
            actual_address = split_start + symbol_offsets[0]
            if suffix_address == actual_address:
                continue

            records.append(
                DriftRecord(
                    source_path=rel,
                    function_name=function_name,
                    suffix_address=suffix_address,
                    actual_address=actual_address,
                    delta=suffix_address - actual_address,
                    comment_address=match.group("v10_addr").strip(),
                )
            )

    delta_counts = Counter(record.delta for record in records)
    print(f"drifting_fun_names={len(records)}")
    print(
        "skipped_missing_split="
        f"{skipped_missing_split} skipped_missing_obj={skipped_missing_obj} "
        f"skipped_missing_symbol={skipped_missing_symbol} skipped_duplicate_symbol={skipped_duplicate_symbol}"
    )
    print("top_deltas:")
    for delta, count in delta_counts.most_common(20):
        print(f"  {delta:+#x} -> {count}")
    print("samples:")
    for record in sorted(records, key=lambda item: (abs(item.delta), item.source_path, item.function_name))[
        : args.limit
    ]:
        print(
            f"  {record.source_path}: {record.function_name} "
            f"suffix=0x{record.suffix_address:08X} actual=0x{record.actual_address:08X} "
            f"delta={record.delta:+#x} comment_v10={record.comment_address}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
