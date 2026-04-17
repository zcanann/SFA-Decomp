from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.orig.dol_xrefs import FunctionSymbol, load_function_symbols
from tools.orig.source_gap_windows import choose_segment_boundaries
from tools.orig.source_recovery import parse_debug_split_text_ranges


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Project a known debug-side file order onto a current EN address range."
    )
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"))
    parser.add_argument(
        "--debug-splits",
        type=Path,
        default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"),
    )
    parser.add_argument("--current-start", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--current-end", type=lambda x: int(x, 0), required=True)
    parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        required=True,
        help="Debug split path to include, in order. Repeat for each file.",
    )
    return parser


def project_interval(
    current_functions: list[FunctionSymbol],
    current_start: int,
    current_end: int,
    debug_split_ranges: dict[str, tuple[int, int]],
    paths: list[str],
) -> tuple[float, list[tuple[str, int, int, int]]] | None:
    functions = [function for function in current_functions if current_start <= function.address < current_end]
    if not functions:
        return None

    current_sizes = [functions[i + 1].address - functions[i].address for i in range(len(functions) - 1)]
    current_sizes.append(current_end - functions[-1].address)

    current_cumulative: list[int] = []
    total = 0
    for size in current_sizes:
        total += size
        current_cumulative.append(total)

    debug_sizes: list[int] = []
    debug_total = 0
    for path in paths:
        start, end = debug_split_ranges[path]
        size = end - start
        debug_sizes.append(size)
        debug_total += size

    scale_ratio = (current_end - current_start) / debug_total
    target_cumulative: list[float] = []
    scaled_total = 0.0
    for size in debug_sizes:
        scaled_total += size * scale_ratio
        target_cumulative.append(scaled_total)

    boundaries = choose_segment_boundaries(current_cumulative, target_cumulative)
    if boundaries is None:
        return None

    projection: list[tuple[str, int, int, int]] = []
    previous = 0
    for path, boundary, debug_size in zip(paths, boundaries, debug_sizes):
        start = functions[previous].address
        end = functions[boundary + 1].address if boundary + 1 < len(functions) else current_end
        projection.append((path, start, end, debug_size))
        previous = boundary + 1
    return scale_ratio, projection


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    current_functions = load_function_symbols(args.symbols)
    debug_split_ranges = parse_debug_split_text_ranges(args.debug_splits)
    normalized_paths = [path.replace("\\", "/") for path in args.paths]

    missing = [path for path in normalized_paths if path not in debug_split_ranges]
    if missing:
        parser.error("unknown debug split path(s): " + ", ".join(missing))

    result = project_interval(
        current_functions=current_functions,
        current_start=args.current_start,
        current_end=args.current_end,
        debug_split_ranges=debug_split_ranges,
        paths=normalized_paths,
    )
    if result is None:
        parser.error("could not project interval onto current EN functions")

    scale_ratio, projection = result
    debug_total = sum(debug_size for _, _, _, debug_size in projection)

    print("# Source interval projection")
    print(
        f"- current range: `0x{args.current_start:08X}-0x{args.current_end:08X}` "
        f"size=`0x{args.current_end - args.current_start:X}`"
    )
    print(f"- debug total size: `0x{debug_total:X}`")
    print(f"- scale ratio: `{scale_ratio:.3f}x`")
    print("- projected windows:")
    for path, start, end, debug_size in projection:
        print(
            f"  - `{path}` `0x{start:08X}-0x{end:08X}` "
            f"size=`0x{end - start:X}` debug=`0x{debug_size:X}`"
        )


if __name__ == "__main__":
    main()
