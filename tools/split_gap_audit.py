import argparse
import json
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_LAYOUT = ROOT / "tools" / "orig" / "source_layout.py"
SDK_PREFIXES = (
    "dolphin/",
    "Runtime.PPCEABI.H/",
)


def classify(path: str) -> str:
    return "sdk" if path.startswith(SDK_PREFIXES) else "game"


def load_text_entries(splits_path: Path):
    text = splits_path.read_text()
    entries = []
    current_path = None
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t")) and line.endswith(":"):
            current_path = line[:-1]
            continue
        if current_path is None or ".text" not in line:
            continue
        match = re.search(r"start:0x([0-9A-Fa-f]+) end:0x([0-9A-Fa-f]+)", line)
        if not match:
            continue
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        entries.append((start, end, current_path, classify(current_path)))
        current_path = None
    return sorted(entries)


def gap_stem(path: str) -> str:
    stem = Path(path).stem
    return stem.lower()


@lru_cache(maxsize=None)
def source_layout_blocks_for_terms(terms: tuple[str, ...], limit: int):
    if not terms:
        return []

    command = [
        sys.executable,
        str(SOURCE_LAYOUT),
        "--format",
        "json",
        "--limit",
        str(limit),
        "--search",
        *terms,
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return []
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    return payload.get("blocks", [])


def summarize_block(block: dict) -> str:
    entries = block.get("entries", [])
    file_names = []
    for entry in entries[:4]:
        name = entry.get("retail_source_name")
        if name:
            file_names.append(name)
    files = ", ".join(file_names) if file_names else "no-names"
    extra = ""
    if len(entries) > 4:
        extra = f", ... (+{len(entries) - 4} more)"
    return (
        f"layout `0x{int(block['start'], 16):08X}-0x{int(block['end'], 16):08X}` "
        f"entries=`{len(entries)}` coverage=`{block.get('coverage', 'n/a')}` "
        f"files=`{files}{extra}`"
    )


def source_clue_summaries(left_path: str, right_path: str, limit: int):
    terms_to_try: list[tuple[str, ...]] = []
    left_game = classify(left_path) == "game"
    right_game = classify(right_path) == "game"
    left_term = gap_stem(left_path)
    right_term = gap_stem(right_path)

    if left_game and right_game and left_term != right_term:
        terms_to_try.append((left_term, right_term))
    if left_game:
        terms_to_try.append((left_term,))
    if right_game:
        terms_to_try.append((right_term,))

    seen: set[tuple[int, int]] = set()
    summaries: list[str] = []
    for terms in terms_to_try:
        for block in source_layout_blocks_for_terms(terms, limit):
            key = (int(block["start"], 16), int(block["end"], 16))
            if key in seen:
                continue
            seen.add(key)
            summaries.append(summarize_block(block))
            if len(summaries) >= limit:
                return summaries
    return summaries


def main():
    parser = argparse.ArgumentParser(description="Audit uncovered .text gaps between split owners.")
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"))
    parser.add_argument("--category", choices=("all", "game", "sdk"), default="all")
    parser.add_argument("--min-gap", type=lambda v: int(v, 0), default=1)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--same-category-only", action="store_true")
    parser.add_argument("--path-contains")
    parser.add_argument(
        "--contains",
        type=lambda v: int(v, 0),
        help="Only show gaps whose uncovered span contains this address.",
    )
    parser.add_argument(
        "--range-start",
        type=lambda v: int(v, 0),
        help="Only show gaps whose uncovered span ends after this address.",
    )
    parser.add_argument(
        "--range-end",
        type=lambda v: int(v, 0),
        help="Only show gaps whose uncovered span starts before this address.",
    )
    parser.add_argument(
        "--source-clues",
        action="store_true",
        help="Attach retail-backed source-layout clue summaries for game-side gap endpoints.",
    )
    parser.add_argument(
        "--source-clue-limit",
        type=int,
        default=1,
        help="Maximum number of source-layout blocks to summarize per gap.",
    )
    args = parser.parse_args()

    entries = load_text_entries(args.splits)
    gaps = []
    for left, right in zip(entries, entries[1:]):
        left_start, left_end, left_path, left_category = left
        right_start, right_end, right_path, right_category = right
        gap = right_start - left_end
        if gap < args.min_gap:
            continue
        if args.same_category_only and left_category != right_category:
            continue
        if args.category != "all" and not (
            left_category == args.category and right_category == args.category
        ):
            continue
        if args.path_contains and args.path_contains not in left_path and args.path_contains not in right_path:
            continue
        if args.contains is not None and not (left_end <= args.contains < right_start):
            continue
        if args.range_start is not None and right_start <= args.range_start:
            continue
        if args.range_end is not None and left_end >= args.range_end:
            continue
        gaps.append((gap, left_end, right_start, left_path, right_path, left_category, right_category))

    gaps.sort(reverse=True)
    print("# Split gap audit")
    print(f"- splits: `{args.splits}`")
    print(f"- category: `{args.category}`")
    print(f"- min gap: `0x{args.min_gap:X}`")
    print(f"- same-category-only: `{args.same_category_only}`")
    if args.contains is not None:
        print(f"- contains: `0x{args.contains:08X}`")
    if args.range_start is not None or args.range_end is not None:
        start_text = f"0x{args.range_start:08X}" if args.range_start is not None else "-inf"
        end_text = f"0x{args.range_end:08X}" if args.range_end is not None else "+inf"
        print(f"- range filter: `{start_text}` to `{end_text}`")
    print(f"- source-clues: `{args.source_clues}`")
    print(f"- matches: `{min(len(gaps), args.limit)}` / `{len(gaps)}`")
    for gap, gap_start, gap_end, left_path, right_path, left_category, right_category in gaps[: args.limit]:
        print(
            f"- `0x{gap_start:08X}-0x{gap_end:08X}` gap=`0x{gap:X}` "
            f"`{left_category}->{right_category}` `{left_path}` -> `{right_path}`"
        )
        if args.source_clues:
            clues = source_clue_summaries(left_path, right_path, args.source_clue_limit)
            if clues:
                for clue in clues:
                    print(f"  source-clue: {clue}")
            elif left_category == "game" or right_category == "game":
                print("  source-clue: none")


if __name__ == "__main__":
    main()
