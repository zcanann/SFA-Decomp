import argparse
import re
from pathlib import Path


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


def main():
    parser = argparse.ArgumentParser(description="Audit uncovered .text gaps between split owners.")
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"))
    parser.add_argument("--category", choices=("all", "game", "sdk"), default="all")
    parser.add_argument("--min-gap", type=lambda v: int(v, 0), default=1)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--same-category-only", action="store_true")
    parser.add_argument("--path-contains")
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
        gaps.append((gap, left_end, right_start, left_path, right_path, left_category, right_category))

    gaps.sort(reverse=True)
    print("# Split gap audit")
    print(f"- splits: `{args.splits}`")
    print(f"- category: `{args.category}`")
    print(f"- min gap: `0x{args.min_gap:X}`")
    print(f"- same-category-only: `{args.same_category_only}`")
    print(f"- matches: `{min(len(gaps), args.limit)}` / `{len(gaps)}`")
    for gap, gap_start, gap_end, left_path, right_path, left_category, right_category in gaps[: args.limit]:
        print(
            f"- `0x{gap_start:08X}-0x{gap_end:08X}` gap=`0x{gap:X}` "
            f"`{left_category}->{right_category}` `{left_path}` -> `{right_path}`"
        )


if __name__ == "__main__":
    main()
